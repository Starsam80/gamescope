#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <array>
#include <atomic>
#include <vector>

#include "log.hpp"
#include "main.hpp"
#include "pipewire.hpp"
#include "rendervulkan.hpp"

#include <spa/debug/types.h>

static LogScope pwr_log("pipewire");

static struct pipewire_state pipewire_state{};

struct buffer_data
{
	std::shared_ptr<CVulkanTexture> texture;
};

class pipewire_lock
{
public:
	pipewire_lock(struct pw_thread_loop *thread): m_thread(thread) { pw_thread_loop_lock(m_thread); }
	~pipewire_lock() { pw_thread_loop_unlock(m_thread); }

	int iterate(int timeout = -1) { return pw_loop_iterate(pw_thread_loop_get_loop(m_thread), timeout); }

private:
	struct pw_thread_loop *m_thread;
};

// Pending buffer for steamcompmgr → PipeWire
static std::atomic<std::shared_ptr<CVulkanTexture>> in_buffer;

static std::vector<const struct spa_pod *> build_format_params(struct spa_pod_builder *builder)
{
	const struct spa_rectangle size = pipewire_state.output_size;
	const struct spa_rectangle min_size = SPA_RECTANGLE(0, 0);
	const struct spa_rectangle max_size = SPA_RECTANGLE(INT32_MAX, INT32_MAX);
	const struct spa_fraction framerate = SPA_FRACTION((uint32_t)g_nOutputRefresh, 1);
	const struct spa_fraction min_framerate = SPA_FRACTION(0, 1);
	const struct spa_fraction max_framerate = SPA_FRACTION(INT32_MAX, 1);

	const auto build = [&](enum spa_video_format format, bool modifier) {
		struct spa_pod_frame obj_frame;
		spa_pod_builder_push_object(builder, &obj_frame, SPA_TYPE_OBJECT_Format, SPA_PARAM_EnumFormat);
		spa_pod_builder_add(builder,
			SPA_FORMAT_mediaType, SPA_POD_Id(SPA_MEDIA_TYPE_video),
			SPA_FORMAT_mediaSubtype, SPA_POD_Id(SPA_MEDIA_SUBTYPE_raw),
			SPA_FORMAT_VIDEO_format, SPA_POD_Id(format),
			SPA_FORMAT_VIDEO_size, SPA_POD_CHOICE_RANGE_Rectangle(&size, &min_size, &max_size),
			SPA_FORMAT_VIDEO_framerate, SPA_POD_CHOICE_RANGE_Fraction(&framerate, &min_framerate, &max_framerate),
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
		if (modifier) {
			spa_pod_builder_prop(builder, SPA_FORMAT_VIDEO_modifier, SPA_POD_PROP_FLAG_MANDATORY);
			spa_pod_builder_long(builder, DRM_FORMAT_MOD_LINEAR);
		}
		return (const struct spa_pod *) spa_pod_builder_pop(builder, &obj_frame);
	};

	return {
		build(SPA_VIDEO_FORMAT_BGRx, true),
		build(SPA_VIDEO_FORMAT_BGRx, false),
		build(SPA_VIDEO_FORMAT_RGBx, true),
		build(SPA_VIDEO_FORMAT_RGBx, false),
		build(SPA_VIDEO_FORMAT_NV12, true),
		build(SPA_VIDEO_FORMAT_NV12, false),
	};
}

static void copy_texture(struct pipewire_state *state, const std::shared_ptr<CVulkanTexture>& compositeImage, bool queue)
{
	if (!state->streaming) {
		return;
	}

	if (queue) {
		in_buffer = compositeImage;
		pw_stream_trigger_process(state->stream);
		return;
	}

	pipewire_lock lock(state->thread);

	struct pw_buffer *pw_buffer = pw_stream_dequeue_buffer(state->stream);
	if (!pw_buffer) {
		pwr_log.errorf("warning: out of buffers");
		return;
	}

	struct buffer_data *extra_data = (struct buffer_data *) pw_buffer->user_data;
	const auto& tex = extra_data->texture;
	vulkan_screenshot(compositeImage, tex);

	struct spa_buffer *spa_buffer = pw_buffer->buffer;

	struct spa_meta_header *header = (struct spa_meta_header *) spa_buffer_find_meta_data(spa_buffer, SPA_META_Header, sizeof(*header));
	if (header != nullptr) {
		header->pts = -1;
		header->flags = 0;
		header->seq = state->seq++;
		header->dts_offset = 0;
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

void pipewire_resize_output(uint32_t width, uint32_t height)
{
	struct pipewire_state *state = &pipewire_state;

	const auto& current = state->video_info.size;
	if (current.width == width && current.height == height) {
		return;
	}

	pwr_log.debugf("renegotiating stream params (size: %dx%d)", width, height);
	pipewire_lock lock(state->thread);
	state->output_size = SPA_RECTANGLE(width, height);

	uint8_t buf[4096];
	struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(buf, sizeof(buf));
	std::vector<const struct spa_pod *> format_params = build_format_params(&builder);
	int ret = pw_stream_update_params(state->stream, format_params.data(), format_params.size());
	if (ret < 0) {
		pwr_log.errorf("pw_stream_update_params failed");
	}
}

static void stream_handle_process(void *data)
{
	struct pipewire_state *state = (struct pipewire_state *) data;

	if (auto compositeImage = in_buffer.exchange(nullptr)) {
		copy_texture(state, compositeImage, false);
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


	int ret = spa_format_video_raw_parse(param, &state->video_info);
	if (ret < 0) {
		pwr_log.errorf("spa_format_video_raw_parse failed");
		return;
	}

	const int blocks = state->video_info.format == SPA_VIDEO_FORMAT_NV12 ? 2 : 1;
	const bool dmabuf = (state->video_info.flags & SPA_VIDEO_FLAG_MODIFIER) != 0;
	const int data_type = 1 << (dmabuf ? SPA_DATA_DmaBuf : SPA_DATA_MemFd);

	uint8_t buf[1024];
	struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(buf, sizeof(buf));

	std::array params = {
		(const struct spa_pod *) spa_pod_builder_add_object(&builder,
			SPA_TYPE_OBJECT_ParamBuffers, SPA_PARAM_Buffers,
			SPA_PARAM_BUFFERS_buffers, SPA_POD_CHOICE_RANGE_Int(4, 1, 32),
			SPA_PARAM_BUFFERS_blocks, SPA_POD_Int(blocks),
			SPA_PARAM_BUFFERS_dataType, SPA_POD_CHOICE_FLAGS_Int(data_type)),
		(const struct spa_pod *) spa_pod_builder_add_object(&builder,
			SPA_TYPE_OBJECT_ParamMeta, SPA_PARAM_Meta,
			SPA_PARAM_META_type, SPA_POD_Id(SPA_META_Header),
			SPA_PARAM_META_size, SPA_POD_Int(sizeof(struct spa_meta_header))),
	};

	ret = pw_stream_update_params(state->stream, params.data(), params.size());
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
		case SPA_VIDEO_FORMAT_BGRx: return DRM_FORMAT_XRGB8888;
		case SPA_VIDEO_FORMAT_RGBx: return DRM_FORMAT_XBGR8888;
		case SPA_VIDEO_FORMAT_NV12: return DRM_FORMAT_NV12;
		default: return DRM_FORMAT_INVALID;
	}
}

EStreamColorspace spa_color_to_gamescope(enum spa_video_color_matrix matrix, enum spa_video_color_range range)
{
	switch (matrix) {
	case SPA_VIDEO_COLOR_MATRIX_BT601:
		switch (range) {
		case SPA_VIDEO_COLOR_RANGE_16_235: return k_EStreamColorspace_BT601;
		case SPA_VIDEO_COLOR_RANGE_0_255: return k_EStreamColorspace_BT601_Full;
		default: return k_EStreamColorspace_Unknown;
		}
	case SPA_VIDEO_COLOR_MATRIX_BT709:
		switch (range) {
		case SPA_VIDEO_COLOR_RANGE_16_235: return k_EStreamColorspace_BT709;
		case SPA_VIDEO_COLOR_RANGE_0_255: return k_EStreamColorspace_BT709_Full;
		default: return k_EStreamColorspace_Unknown;
		}
	default: return k_EStreamColorspace_Unknown;
	}
}

static void stream_handle_add_buffer(void *user_data, struct pw_buffer *pw_buffer)
{
	struct pipewire_state *state = (struct pipewire_state *) user_data;

	struct buffer_data *extra_data = new buffer_data();
	pw_buffer->user_data = extra_data;

	uint32_t drmFormat = spa_format_to_drm(state->video_info.format);

	const bool is_dmabuf = (state->video_info.flags & SPA_VIDEO_FLAG_MODIFIER) != 0;
	if (is_dmabuf) assert(state->video_info.modifier == DRM_FORMAT_MOD_LINEAR);

	extra_data->texture = vulkan_create_screenshot_texture(state->video_info.size.width, state->video_info.size.height, drmFormat, is_dmabuf);
	const auto& tex = extra_data->texture;

	EStreamColorspace colorspace = spa_color_to_gamescope(state->video_info.color_matrix, state->video_info.color_range);
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
	struct buffer_data *extra_data = (struct buffer_data *) pw_buffer->user_data;
	delete extra_data;

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

	state->output_size = SPA_RECTANGLE(g_nOutputWidth, g_nOutputHeight);

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

bool pipewire_is_streaming(void)
{
	struct pipewire_state *state = &pipewire_state;
	return state->streaming;
}

void pipewire_copy_texture(const std::shared_ptr<CVulkanTexture>& compositeImage, bool queue)
{
	struct pipewire_state *state = &pipewire_state;
	copy_texture(state, compositeImage, queue);
}

void nudge_pipewire(void)
{
	struct pipewire_state *state = &pipewire_state;
	pw_stream_trigger_process(state->stream);
}
