#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <atomic>
#include <vector>

#include "log.hpp"
#include "main.hpp"
#include "pipewire.hpp"
#include "pipewire_requested_size.hpp"

#include <spa/debug/types.h>

static LogScope pwr_log("pipewire");

static struct pipewire_state pipewire_state{};

class pipewire_lock
{
public:
	pipewire_lock(struct pw_thread_loop *thread): m_thread(thread) { pw_thread_loop_lock(m_thread); }
	~pipewire_lock() { pw_thread_loop_unlock(m_thread); }

	int iterate(int timeout = -1) { return pw_loop_iterate(pw_thread_loop_get_loop(m_thread), timeout); }

private:
	struct pw_thread_loop *m_thread;
};

// Pending buffer for PipeWire → steamcompmgr
static std::atomic<struct pipewire_buffer *> out_buffer;
// Pending buffer for steamcompmgr → PipeWire
static std::atomic<struct pipewire_buffer *> in_buffer;

// Requested capture size
static uint32_t s_nRequestedWidth;
static uint32_t s_nRequestedHeight;
static uint32_t s_nCaptureWidth;
static uint32_t s_nCaptureHeight;
static uint32_t s_nOutputWidth;
static uint32_t s_nOutputHeight;

static void calculate_capture_size()
{
	s_nCaptureWidth = s_nOutputWidth;
	s_nCaptureHeight = s_nOutputHeight;

	if (s_nRequestedWidth > 0 && s_nRequestedHeight > 0 &&
	    (s_nOutputWidth > s_nRequestedWidth || s_nOutputHeight > s_nRequestedHeight)) {
		// Need to clamp to the smallest dimension
		float flRatioW = static_cast<float>(s_nRequestedWidth) / s_nOutputWidth;
		float flRatioH = static_cast<float>(s_nRequestedHeight) / s_nOutputHeight;
		if (flRatioW <= flRatioH) {
			s_nCaptureWidth = s_nRequestedWidth;
			s_nCaptureHeight = static_cast<uint32_t>(ceilf(flRatioW * s_nOutputHeight));
		} else {
			s_nCaptureWidth = static_cast<uint32_t>(ceilf(flRatioH * s_nOutputWidth));
			s_nCaptureHeight = s_nRequestedHeight;
		}
	}
}

static void build_format_params(struct spa_pod_builder *builder, spa_video_format format, std::vector<const struct spa_pod *> &params) {
	struct spa_rectangle size = SPA_RECTANGLE(s_nCaptureWidth, s_nCaptureHeight);
	struct spa_rectangle min_requested_size = { 0, 0 };
	struct spa_rectangle max_requested_size = { UINT32_MAX, UINT32_MAX };
	struct spa_fraction framerate = SPA_FRACTION(0, 1);
	uint64_t modifier = DRM_FORMAT_MOD_LINEAR;

	struct spa_pod_frame obj_frame, choice_frame;
	spa_pod_builder_push_object(builder, &obj_frame, SPA_TYPE_OBJECT_Format, SPA_PARAM_EnumFormat);
	spa_pod_builder_add(builder,
		SPA_FORMAT_mediaType, SPA_POD_Id(SPA_MEDIA_TYPE_video),
		SPA_FORMAT_mediaSubtype, SPA_POD_Id(SPA_MEDIA_SUBTYPE_raw),
		SPA_FORMAT_VIDEO_format, SPA_POD_Id(format),
		SPA_FORMAT_VIDEO_size, SPA_POD_Rectangle(&size),
		SPA_FORMAT_VIDEO_framerate, SPA_POD_Fraction(&framerate),
		SPA_FORMAT_VIDEO_requested_size, SPA_POD_CHOICE_RANGE_Rectangle( &min_requested_size, &min_requested_size, &max_requested_size ),
		0);
	if (format == SPA_VIDEO_FORMAT_NV12) {
		spa_pod_builder_add(builder,
			SPA_FORMAT_VIDEO_colorMatrix, SPA_POD_CHOICE_ENUM_Id(3,
							SPA_VIDEO_COLOR_MATRIX_BT601,
							SPA_VIDEO_COLOR_MATRIX_BT601,
							SPA_VIDEO_COLOR_MATRIX_BT709),
			SPA_FORMAT_VIDEO_colorRange, SPA_POD_CHOICE_ENUM_Id(3,
							SPA_VIDEO_COLOR_RANGE_16_235,
							SPA_VIDEO_COLOR_RANGE_16_235,
							SPA_VIDEO_COLOR_RANGE_0_255),
			0);
	}
	spa_pod_builder_prop(builder, SPA_FORMAT_VIDEO_modifier, SPA_POD_PROP_FLAG_MANDATORY);
	spa_pod_builder_push_choice(builder, &choice_frame, SPA_CHOICE_Enum, 0);
	spa_pod_builder_long(builder, modifier); // default
	spa_pod_builder_long(builder, modifier);
	spa_pod_builder_pop(builder, &choice_frame);
	params.push_back((const struct spa_pod *) spa_pod_builder_pop(builder, &obj_frame));

	spa_pod_builder_push_object(builder, &obj_frame, SPA_TYPE_OBJECT_Format, SPA_PARAM_EnumFormat);
	spa_pod_builder_add(builder,
		SPA_FORMAT_mediaType, SPA_POD_Id(SPA_MEDIA_TYPE_video),
		SPA_FORMAT_mediaSubtype, SPA_POD_Id(SPA_MEDIA_SUBTYPE_raw),
		SPA_FORMAT_VIDEO_format, SPA_POD_Id(format),
		SPA_FORMAT_VIDEO_size, SPA_POD_Rectangle(&size),
		SPA_FORMAT_VIDEO_framerate, SPA_POD_Fraction(&framerate),
		SPA_FORMAT_VIDEO_requested_size, SPA_POD_CHOICE_RANGE_Rectangle( &min_requested_size, &min_requested_size, &max_requested_size ),
		0);
	if (format == SPA_VIDEO_FORMAT_NV12) {
		spa_pod_builder_add(builder,
			SPA_FORMAT_VIDEO_colorMatrix, SPA_POD_CHOICE_ENUM_Id(3,
							SPA_VIDEO_COLOR_MATRIX_BT601,
							SPA_VIDEO_COLOR_MATRIX_BT601,
							SPA_VIDEO_COLOR_MATRIX_BT709),
			SPA_FORMAT_VIDEO_colorRange, SPA_POD_CHOICE_ENUM_Id(3,
							SPA_VIDEO_COLOR_RANGE_16_235,
							SPA_VIDEO_COLOR_RANGE_16_235,
							SPA_VIDEO_COLOR_RANGE_0_255),
			0);
	}
	params.push_back((const struct spa_pod *) spa_pod_builder_pop(builder, &obj_frame));
}


static std::vector<const struct spa_pod *> build_format_params(struct spa_pod_builder *builder)
{
	std::vector<const struct spa_pod *> params;

	build_format_params(builder, SPA_VIDEO_FORMAT_BGRx, params);
	build_format_params(builder, SPA_VIDEO_FORMAT_NV12, params);

	return params;
}

static void request_buffer(struct pipewire_state *state)
{
	struct pw_buffer *pw_buffer = pw_stream_dequeue_buffer(state->stream);
	if (!pw_buffer) {
		pwr_log.errorf("warning: out of buffers");
		return;
	}

	struct pipewire_buffer *buffer = (struct pipewire_buffer *) pw_buffer->user_data;
	buffer->copying = true;

	// Past this exchange, the PipeWire thread shares the buffer with the
	// steamcompmgr thread
	struct pipewire_buffer *old = out_buffer.exchange(buffer);
	assert(old == nullptr);
}

static void copy_buffer(struct pipewire_state *state, struct pipewire_buffer *buffer)
{
	buffer->copying = false;

	struct pw_buffer *pw_buffer = buffer->buffer;
	if (!pw_buffer) {
		delete buffer;
		return;
	}

	const auto& tex = buffer->texture;
	assert(tex != nullptr);

	struct spa_buffer *spa_buffer = pw_buffer->buffer;

	struct spa_meta_header *header = (struct spa_meta_header *) spa_buffer_find_meta_data(spa_buffer, SPA_META_Header, sizeof(*header));
	if (header != nullptr) {
		header->pts = -1;
		header->flags = 0;
		header->seq = state->seq++;
		header->dts_offset = 0;
	}

	float *requested_size_scale = (float *) spa_buffer_find_meta_data(spa_buffer, SPA_META_requested_size_scale, sizeof(*requested_size_scale));
	if (requested_size_scale != nullptr) {
		*requested_size_scale = ((float)tex->width() / g_nOutputWidth);
	}

	for (uint32_t i = 0; i < spa_buffer->n_datas; i++) {
		struct spa_data *d = &spa_buffer->datas[i];

		const auto& layout = tex->planeLayout(i);
		d->chunk->offset = 0;
		d->chunk->size = layout.size;
		d->chunk->stride = layout.rowPitch;

		if (d->type == SPA_DATA_MemFd) {
			memcpy(d->data, tex->mappedData() + layout.offset, d->chunk->size);
		}
	}

	int ret = pw_stream_queue_buffer(state->stream, pw_buffer);
	if (ret < 0) {
		pwr_log.errorf("pw_stream_queue_buffer failed");
	}
}

static void stream_handle_process(void *data)
{
	struct pipewire_state *state = (struct pipewire_state *) data;

	if (g_nOutputWidth != s_nOutputWidth || g_nOutputHeight != s_nOutputHeight) {
		s_nOutputWidth = g_nOutputWidth;
		s_nOutputHeight = g_nOutputHeight;
		calculate_capture_size();
	}
	if (s_nCaptureWidth != state->video_info.size.width || s_nCaptureHeight != state->video_info.size.height) {
		pwr_log.debugf("renegotiating stream params (size: %dx%d)", s_nCaptureWidth, s_nCaptureHeight);

		uint8_t buf[4096];
		struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(buf, sizeof(buf));
		std::vector<const struct spa_pod *> format_params = build_format_params(&builder);
		int ret = pw_stream_update_params(state->stream, format_params.data(), format_params.size());
		if (ret < 0) {
			pwr_log.errorf("pw_stream_update_params failed");
		}
	}

	struct pipewire_buffer *buffer = in_buffer.exchange(nullptr);
	if (buffer != nullptr) {
		// We now completely own the buffer, it's no longer shared with the
		// steamcompmgr thread.

		copy_buffer(state, buffer);
	}
}

static void stream_handle_state_changed(void *data, enum pw_stream_state old_stream_state, enum pw_stream_state stream_state, const char *error)
{
	struct pipewire_state *state = (struct pipewire_state *) data;

	pwr_log.debugf("stream state changed: %s", pw_stream_state_as_string(stream_state));

	switch (stream_state) {
	case PW_STREAM_STATE_PAUSED:
		if (state->stream_node_id == SPA_ID_INVALID) {
			state->stream_node_id = pw_stream_get_node_id(state->stream);
		}
		state->streaming = false;
		state->seq = 0;
		break;
	case PW_STREAM_STATE_STREAMING:
		state->streaming = true;
		break;
	default:
		break;
	}
}

static void stream_handle_param_changed(void *data, uint32_t id, const struct spa_pod *param)
{
	struct pipewire_state *state = (struct pipewire_state *) data;

	if (param == nullptr || id != SPA_PARAM_Format)
		return;

	struct spa_rectangle requested_size = { 0, 0 };

	int ret = spa_format_video_raw_parse_with_requested_size(param, &state->video_info, &requested_size);
	if (ret < 0) {
		pwr_log.errorf("spa_format_video_raw_parse failed");
		return;
	}
	s_nRequestedWidth = requested_size.width;
	s_nRequestedHeight = requested_size.height;
	calculate_capture_size();

	const int blocks = state->video_info.format == SPA_VIDEO_FORMAT_NV12 ? 2 : 1;
	const bool dmabuf = (state->video_info.flags & SPA_VIDEO_FLAG_MODIFIER) != 0;
	const int data_type = 1 << (dmabuf ? SPA_DATA_DmaBuf : SPA_DATA_MemFd);

	uint8_t buf[1024];
	struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(buf, sizeof(buf));

	const struct spa_pod *buffers_param =
		(const struct spa_pod *) spa_pod_builder_add_object(&builder,
		SPA_TYPE_OBJECT_ParamBuffers, SPA_PARAM_Buffers,
		SPA_PARAM_BUFFERS_buffers, SPA_POD_CHOICE_RANGE_Int(4, 1, 32),
		SPA_PARAM_BUFFERS_blocks, SPA_POD_Int(blocks),
		SPA_PARAM_BUFFERS_dataType, SPA_POD_CHOICE_FLAGS_Int(data_type));
	const struct spa_pod *meta_param =
		(const struct spa_pod *) spa_pod_builder_add_object(&builder,
		SPA_TYPE_OBJECT_ParamMeta, SPA_PARAM_Meta,
		SPA_PARAM_META_type, SPA_POD_Id(SPA_META_Header),
		SPA_PARAM_META_size, SPA_POD_Int(sizeof(struct spa_meta_header)));
	const struct spa_pod *scale_param =
		(const struct spa_pod *) spa_pod_builder_add_object(&builder,
		SPA_TYPE_OBJECT_ParamMeta, SPA_PARAM_Meta,
		SPA_PARAM_META_type, SPA_POD_Id(SPA_META_requested_size_scale),
		SPA_PARAM_META_size, SPA_POD_Int(sizeof(float)));
	const struct spa_pod *params[] = { buffers_param, meta_param, scale_param };

	ret = pw_stream_update_params(state->stream, params, sizeof(params) / sizeof(params[0]));
	if (ret != 0) {
		pwr_log.errorf("pw_stream_update_params failed");
	}

	pwr_log.debugf("format changed (size: %dx%d, format: %s, flags: %d)",
		state->video_info.size.width, state->video_info.size.height,
		spa_debug_type_find_short_name(spa_type_video_format, state->video_info.format),
		state->video_info.flags);
}

static void randname(char *buf)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	long r = ts.tv_nsec;
	for (int i = 0; i < 6; ++i) {
		buf[i] = 'A'+(r&15)+(r&16)*2;
		r >>= 5;
	}
}

static int anonymous_shm_open(void)
{
	char name[] = "/gamescope-pw-XXXXXX";
	int retries = 100;

	do {
		randname(name + strlen(name) - 6);

		--retries;
		// shm_open guarantees that O_CLOEXEC is set
		int fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
		if (fd >= 0) {
			shm_unlink(name);
			return fd;
		}
	} while (retries > 0 && errno == EEXIST);

	return -1;
}

uint32_t spa_format_to_drm(uint32_t spa_format)
{
	switch (spa_format)
	{
		case SPA_VIDEO_FORMAT_NV12: return DRM_FORMAT_NV12;
		default:
		case SPA_VIDEO_FORMAT_BGR: return DRM_FORMAT_XRGB8888;
	}
}

static void stream_handle_add_buffer(void *user_data, struct pw_buffer *pw_buffer)
{
	struct pipewire_state *state = (struct pipewire_state *) user_data;

	struct pipewire_buffer *extra_data = new pipewire_buffer();
	pw_buffer->user_data = extra_data;
	extra_data->buffer = pw_buffer;

	uint32_t drmFormat = spa_format_to_drm(state->video_info.format);

	const bool is_dmabuf = (state->video_info.flags & SPA_VIDEO_FLAG_MODIFIER) != 0;
	if (is_dmabuf) assert(state->video_info.modifier == DRM_FORMAT_MOD_LINEAR);

	extra_data->texture = vulkan_create_screenshot_texture(s_nCaptureWidth, s_nCaptureHeight, drmFormat, is_dmabuf);
	const auto& tex = extra_data->texture;

	EStreamColorspace colorspace = k_EStreamColorspace_Unknown;
	switch (state->video_info.color_matrix) {
	case SPA_VIDEO_COLOR_MATRIX_BT601:
		switch (state->video_info.color_range) {
		case SPA_VIDEO_COLOR_RANGE_16_235:
			colorspace = k_EStreamColorspace_BT601;
			break;
		case SPA_VIDEO_COLOR_RANGE_0_255:
			colorspace = k_EStreamColorspace_BT601_Full;
			break;
		default:
			break;
		}
		break;
	case SPA_VIDEO_COLOR_MATRIX_BT709:
		switch (state->video_info.color_range) {
		case SPA_VIDEO_COLOR_RANGE_16_235:
			colorspace = k_EStreamColorspace_BT709;
			break;
		case SPA_VIDEO_COLOR_RANGE_0_255:
			colorspace = k_EStreamColorspace_BT709_Full;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
	tex->setStreamColorspace(colorspace);

	struct spa_buffer *spa_buffer = pw_buffer->buffer;
	for (uint32_t i = 0; i < spa_buffer->n_datas; i++) {
		struct spa_data *d = &spa_buffer->datas[i];
		const auto& layout = tex->planeLayout(i);

		if ((d->type & (1 << SPA_DATA_DmaBuf)) != 0) {
			d->type = SPA_DATA_DmaBuf;
			d->flags = SPA_DATA_FLAG_READABLE;

			d->fd = tex->dmabuf().fd[i];
			d->maxsize = layout.size;
			d->mapoffset = layout.offset;
			d->data = nullptr;
		} else if ((d->type & (1 << SPA_DATA_MemFd)) != 0) {
			d->type = SPA_DATA_MemFd;
			d->flags = SPA_DATA_FLAG_READABLE;

			d->fd = anonymous_shm_open();
			if (d->fd < 0) {
				pwr_log.errorf("failed to create shm file");
				return;
			}

			d->maxsize = layout.size;
			if (ftruncate(d->fd, d->maxsize) != 0) {
				pwr_log.errorf_errno("ftruncate failed");
				close(d->fd);
				return;
			}

			d->mapoffset = 0;
			d->data = mmap(NULL, d->maxsize, PROT_READ | PROT_WRITE, MAP_SHARED, d->fd, d->mapoffset);
			if (d->data == MAP_FAILED) {
				pwr_log.errorf_errno("mmap failed");
				close(d->fd);
				return;
			}
		} else {
			pwr_log.errorf("unsupported data type");
			d->type = SPA_DATA_Invalid;
		}
	}
}

static void stream_handle_remove_buffer(void *data, struct pw_buffer *pw_buffer)
{
	struct pipewire_buffer *extra_data = (struct pipewire_buffer *) pw_buffer->user_data;
	extra_data->buffer = nullptr;

	if (!extra_data->copying) {
		delete extra_data;
	}

	struct spa_buffer *spa_buffer = pw_buffer->buffer;
	for (uint32_t i = 0; i < spa_buffer->n_datas; i++) {
		struct spa_data *d = &spa_buffer->datas[i];

		if (d->type == SPA_DATA_MemFd) {
			munmap(d->data, d->maxsize);
			close(d->fd);
		}
	}
}

static const struct pw_stream_events stream_events = {
	.version = PW_VERSION_STREAM_EVENTS,
	.state_changed = stream_handle_state_changed,
	.param_changed = stream_handle_param_changed,
	.add_buffer = stream_handle_add_buffer,
	.remove_buffer = stream_handle_remove_buffer,
	.process = stream_handle_process,
};

pipewire_state::pipewire_state()
{
	pw_init(nullptr, nullptr);
}

pipewire_state::~pipewire_state()
{
	struct pipewire_state *state = this;
	if (state->thread) {
		pw_thread_loop_stop(state->thread);
		if (state->stream) {
			pw_stream_destroy(state->stream);
		}
		if (state->core) {
			pw_core_disconnect(state->core);
		}
		if (state->context) {
			pw_context_destroy(state->context);
		}
		pw_thread_loop_destroy(state->thread);
	}
	pw_deinit();
}

bool init_pipewire(void)
{
	struct pipewire_state *state = &pipewire_state;

	state->thread = pw_thread_loop_new("gamescope-pw", nullptr);
	if (!state->thread) {
		pwr_log.errorf("pw_thread_loop_new failed");
		return false;
	}

	pipewire_lock lock(state->thread);
	pw_thread_loop_start(state->thread);

	state->context = pw_context_new(pw_thread_loop_get_loop(state->thread), nullptr, 0);
	if (!state->context) {
		pwr_log.errorf("pw_context_new failed");
		return false;
	}

	state->core = pw_context_connect(state->context, nullptr, 0);
	if (!state->core) {
		pwr_log.errorf("pw_context_connect failed");
		return false;
	}

	state->stream = pw_stream_new(state->core, "gamescope",
		pw_properties_new(
			PW_KEY_MEDIA_CLASS, "Video/Source",
			nullptr));
	if (!state->stream) {
		pwr_log.errorf("pw_stream_new failed");
		return false;
	}

	static struct spa_hook stream_hook;
	pw_stream_add_listener(state->stream, &stream_hook, &stream_events, state);

	s_nRequestedWidth = 0;
	s_nRequestedHeight = 0;
	s_nOutputWidth = g_nOutputWidth;
	s_nOutputHeight = g_nOutputHeight;
	calculate_capture_size();

	uint8_t buf[4096];
	struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(buf, sizeof(buf));
	std::vector<const struct spa_pod *> format_params = build_format_params(&builder);

	enum pw_stream_flags flags = (enum pw_stream_flags)(PW_STREAM_FLAG_DRIVER | PW_STREAM_FLAG_ALLOC_BUFFERS);
	int ret = pw_stream_connect(state->stream, PW_DIRECTION_OUTPUT, PW_ID_ANY, flags, format_params.data(), format_params.size());
	if (ret != 0) {
		pwr_log.errorf("pw_stream_connect failed");
		return false;
	}

	while (state->stream_node_id == SPA_ID_INVALID) {
		if (lock.iterate() < 0) {
			pwr_log.errorf("pw_loop_iterate failed");
			return false;
		}
	}

	pwr_log.infof("stream available on node ID: %u", state->stream_node_id);

	return true;
}

uint32_t get_pipewire_stream_node_id(void)
{
	return pipewire_state.stream_node_id;
}

struct pipewire_buffer *dequeue_pipewire_buffer(void)
{
	struct pipewire_state *state = &pipewire_state;
	if (state->streaming) {
		request_buffer(state);
	}
	return out_buffer.exchange(nullptr);
}

void push_pipewire_buffer(struct pipewire_buffer *buffer)
{
	struct pipewire_buffer *old = in_buffer.exchange(buffer);
	assert(old == nullptr);
	nudge_pipewire();
}

void nudge_pipewire(void)
{
	struct pipewire_state *state = &pipewire_state;
	pw_stream_trigger_process(state->stream);
}
