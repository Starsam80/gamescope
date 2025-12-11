
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include <atomic>
#include <thread>
#include <vector>

#include "main.hpp"
#include "pipewire.hpp"
#include "log.hpp"

#include <spa/debug/format.h>

static LogScope pwr_log("pipewire");

static struct pipewire_state pipewire_state = { .stream_node_id = SPA_ID_INVALID };

// Pending buffer for PipeWire → steamcompmgr
static std::atomic<struct pipewire_buffer *> out_buffer;
// Pending buffer for steamcompmgr → PipeWire
static std::atomic<struct pipewire_buffer *> in_buffer;

static void destroy_buffer(struct pipewire_buffer *buffer) {
	assert(buffer->buffer == nullptr);
	delete buffer;
}

void pipewire_destroy_buffer(struct pipewire_buffer *buffer)
{
	destroy_buffer(buffer);
}

static const struct spa_pod *build_format_params(struct spa_pod_builder *builder, const enum spa_video_format format, const std::span<const uint64_t>& modifiers)
{
	struct spa_rectangle size = SPA_RECTANGLE(g_nNestedWidth, g_nNestedHeight);
	struct spa_rectangle min_size = SPA_RECTANGLE(1, 1);
	struct spa_rectangle max_size = SPA_RECTANGLE(INT32_MAX, INT32_MAX);
	struct spa_fraction framerate = SPA_FRACTION(0, 1);

	struct spa_pod_frame obj_frame;
	spa_pod_builder_push_object(builder, &obj_frame, SPA_TYPE_OBJECT_Format, SPA_PARAM_EnumFormat);
	spa_pod_builder_add(builder,
		SPA_FORMAT_mediaType, SPA_POD_Id(SPA_MEDIA_TYPE_video),
		SPA_FORMAT_mediaSubtype, SPA_POD_Id(SPA_MEDIA_SUBTYPE_raw),
		SPA_FORMAT_VIDEO_format, SPA_POD_Id(format),
		SPA_FORMAT_VIDEO_size, SPA_POD_CHOICE_RANGE_Rectangle(&size, &min_size, &max_size),
		SPA_FORMAT_VIDEO_framerate, SPA_POD_Fraction(&framerate),
		SPA_FORMAT_VIDEO_gamescope_focus_appid, SPA_POD_CHOICE_RANGE_Long( 0ll, INT64_MIN, INT64_MAX ),
		0);
	if (format == SPA_VIDEO_FORMAT_NV12) {
		spa_pod_builder_add(builder,
			SPA_FORMAT_VIDEO_colorMatrix, SPA_POD_CHOICE_ENUM_Id(3,
							SPA_VIDEO_COLOR_MATRIX_BT709,
							SPA_VIDEO_COLOR_MATRIX_BT709,
							SPA_VIDEO_COLOR_MATRIX_BT601),
			SPA_FORMAT_VIDEO_colorRange, SPA_POD_CHOICE_ENUM_Id(3,
							SPA_VIDEO_COLOR_RANGE_16_235,
							SPA_VIDEO_COLOR_RANGE_16_235,
							SPA_VIDEO_COLOR_RANGE_0_255),
			0);
	}
	if (modifiers.size() == 1) {
		// Pre-fixate if there is only one modifier
		spa_pod_builder_prop(builder, SPA_FORMAT_VIDEO_modifier, SPA_POD_PROP_FLAG_MANDATORY);
		spa_pod_builder_long(builder, modifiers[0]);
	} else if (modifiers.size() > 0) {
		struct spa_pod_frame choice_frame;
		spa_pod_builder_prop(builder, SPA_FORMAT_VIDEO_modifier, SPA_POD_PROP_FLAG_MANDATORY | SPA_POD_PROP_FLAG_DONT_FIXATE);
		spa_pod_builder_push_choice(builder, &choice_frame, SPA_CHOICE_Enum, 0);
		spa_pod_builder_long(builder, modifiers[0]); // default, but should be ignored because of FLAG_DONT_FIXATE
		for (const uint64_t modifier : modifiers) {
			spa_pod_builder_long(builder, modifier);
		}
		spa_pod_builder_pop(builder, &choice_frame);
	}
	return (const struct spa_pod *) spa_pod_builder_pop(builder, &obj_frame);
}


static std::vector<const struct spa_pod *> build_format_params(struct spa_pod_builder *builder, const struct spa_video_info_raw *fixated = nullptr)
{
	std::vector<const struct spa_pod *> params;

	if (fixated != nullptr) {
		params.push_back(spa_format_video_raw_build(builder, SPA_PARAM_EnumFormat, fixated));
	}

	for (const enum spa_video_format format : {
		SPA_VIDEO_FORMAT_BGRx,
		SPA_VIDEO_FORMAT_NV12,
	}) {
		const uint32_t drmFormat = spa_format_to_drm(format);
		std::span<const uint64_t> modifiers = GetSupportedSampleModifiers(drmFormat);
		if (modifiers.size() != 0) 
			params.push_back(build_format_params(builder, format, modifiers));
		params.push_back(build_format_params(builder, format, {}));
	}

//	for (auto& param : params)
//		spa_debug_format(2, nullptr, param);
	return params;
}

static struct pipewire_buffer *dequeue_buffer(struct pipewire_state *state)
{
	struct pw_buffer *pw_buffer = pw_stream_dequeue_buffer(state->stream);
	if (!pw_buffer) {
		pwr_log.warnf("out of buffers");
		return nullptr;
	}
	struct pipewire_buffer *buffer = (struct pipewire_buffer *) pw_buffer->user_data;
	// Past this exchange, the PipeWire thread shares the buffer with the steamcompmgr thread
	buffer->copying = true;
	return buffer;
}

static void stream_handle_process(void *data)
{
	struct pipewire_state *state = (struct pipewire_state *) data;

	if (out_buffer == nullptr) {
		out_buffer = dequeue_buffer(state);
	}

	struct pipewire_buffer *buffer = in_buffer.exchange(nullptr);
	if (buffer == nullptr) {
		// Nothing was submitted
		return;
	}
	// We now completely own the buffer, it's no longer shared with the steamcompmgr thread.
	buffer->copying = false;

	if (buffer->IsStale()) {
		destroy_buffer(buffer);
		return;
	}

	struct pw_buffer *pw_buffer = buffer->buffer;
	struct spa_buffer *spa_buffer = pw_buffer->buffer;

	struct spa_meta_header *header = (struct spa_meta_header *) spa_buffer_find_meta_data(spa_buffer, SPA_META_Header, sizeof(*header));
	if (header != nullptr) {
		header->pts = buffer->pts;
		header->flags = 0;
		header->seq = state->seq++;
		header->dts_offset = 0;
	}

	int ret = pw_stream_queue_buffer(state->stream, pw_buffer);
	if (ret < 0) {
		pwr_log.errorf("pw_stream_queue_buffer failed");
	}
}

static void on_nudge(void *data, int fd, uint32_t mask)
{
	struct pipewire_state *state = (struct pipewire_state *) data;

	while (true) {
		static char buf[1024];
		if (read(fd, buf, sizeof(buf)) < 0) {
			if (errno != EAGAIN)
				pwr_log.errorf_errno("dispatch_nudge: read failed");
			break;
		}
	}

	pw_stream_trigger_process(state->stream);
}

static void stream_handle_state_changed(void *data, enum pw_stream_state old_stream_state, enum pw_stream_state stream_state, const char *error)
{
	struct pipewire_state *state = (struct pipewire_state *) data;

	pwr_log.infof("stream state changed: %s", pw_stream_state_as_string(stream_state));

	state->streaming = stream_state == PW_STREAM_STATE_STREAMING;

	if (error != nullptr) {
		pwr_log.errorf("stream error: %s", error);
	}

	switch (stream_state) {
	case PW_STREAM_STATE_PAUSED:
		state->stream_node_id = pw_stream_get_node_id(state->stream);
		pwr_log.infof("stream available on node ID: %u", state->stream_node_id);
		state->seq = 0;
		break;
	case PW_STREAM_STATE_STREAMING:
	case PW_STREAM_STATE_ERROR:
	case PW_STREAM_STATE_UNCONNECTED:
	default:
		break;
	}
}

static void stream_handle_param_changed(void *data, uint32_t id, const struct spa_pod *param)
{
	struct pipewire_state *state = (struct pipewire_state *) data;

	if (param == nullptr || id != SPA_PARAM_Format)
		return;

	struct spa_gamescope gamescope_info{};

	int ret = spa_format_video_raw_parse_with_gamescope(param, &state->video_info, &gamescope_info);
	if (ret < 0) {
		pwr_log.errorf("spa_format_video_raw_parse failed");
		return;
	}
	state->gamescope_info = gamescope_info;

	CVulkanTexture::createFlags probeFlags;
	probeFlags.bTransferDst = true;
	probeFlags.bStorage = true;

	const struct spa_pod_prop *modifier_prop = spa_pod_find_prop(param, NULL, SPA_FORMAT_VIDEO_modifier);
	if (modifier_prop) {
		uint32_t n_values, choice;
		struct spa_pod *values = spa_pod_get_values(&modifier_prop->value, &n_values, &choice);
		assert(choice == SPA_CHOICE_None || choice == SPA_CHOICE_Enum);

		probeFlags.exportModifiers = {(const uint64_t *) SPA_POD_BODY(values), n_values};
	}

	probeFlags.bExportable = true;
	if (probeFlags.exportModifiers.size() == 0) {
		probeFlags.bMappable = true;
		SPA_FLAG_CLEAR(state->video_info.flags, SPA_VIDEO_FLAG_MODIFIER);
	}

	const uint32_t drmFormat = spa_format_to_drm(state->video_info.format);
	CVulkanTexture tex;
	if (!tex.BInit(state->video_info.size.width, state->video_info.size.height, 1u, drmFormat, probeFlags)) {
		pwr_log.errorf("texture probe failed");
		return;
	}

	const auto& dmabuf = tex.dmabuf();
	state->video_info.modifier = dmabuf.modifier;
	int blocks = dmabuf.n_planes;

	// Always expose DMA-BUF capabilities (allow modifier-less exports)
	int data_type = (1 << SPA_DATA_DmaBuf);
	if (!SPA_FLAG_IS_SET(state->video_info.flags, SPA_VIDEO_FLAG_MODIFIER))
		data_type |= (1 << SPA_DATA_MemFd);

	uint8_t buf[4096];
	struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(buf, sizeof(buf));
	std::vector<const struct spa_pod *> params;

	if (SPA_FLAG_IS_SET(state->video_info.flags, SPA_VIDEO_FLAG_MODIFIER_FIXATION_REQUIRED)) {
		SPA_FLAG_CLEAR(state->video_info.flags, SPA_VIDEO_FLAG_MODIFIER_FIXATION_REQUIRED);
		params = build_format_params(&builder, &state->video_info);
	} else {
		params = {
			(const struct spa_pod *) spa_pod_builder_add_object(&builder,
				SPA_TYPE_OBJECT_ParamBuffers, SPA_PARAM_Buffers,
				SPA_PARAM_BUFFERS_buffers, SPA_POD_CHOICE_RANGE_Int(4, 1, 8),
				SPA_PARAM_BUFFERS_blocks, SPA_POD_Int(blocks),
				SPA_PARAM_BUFFERS_size, SPA_POD_CHOICE_RANGE_Int(0, 0, INT32_MAX),
				SPA_PARAM_BUFFERS_stride, SPA_POD_CHOICE_RANGE_Int(0, 0, INT32_MAX),
				SPA_PARAM_BUFFERS_dataType, SPA_POD_CHOICE_FLAGS_Int(data_type)),
			(const struct spa_pod *) spa_pod_builder_add_object(&builder,
				SPA_TYPE_OBJECT_ParamMeta, SPA_PARAM_Meta,
				SPA_PARAM_META_type, SPA_POD_Id(SPA_META_Header),
				SPA_PARAM_META_size, SPA_POD_Int(sizeof(struct spa_meta_header)))
		};
	}

	ret = pw_stream_update_params(state->stream, params.data(), params.size());
	if (ret != 0) {
		pwr_log.errorf("pw_stream_update_params failed");
	}

	pwr_log.debugf("format changed (size: %dx%d, format: %d)",
		state->video_info.size.width, state->video_info.size.height,
		state->video_info.format);
}

static constexpr EStreamColorspace spa_color_to_gamescope(const struct spa_video_info_raw& video_info)
{
	switch (video_info.color_matrix) {
	case SPA_VIDEO_COLOR_MATRIX_BT601:
		switch (video_info.color_range) {
		case SPA_VIDEO_COLOR_RANGE_16_235: return k_EStreamColorspace_BT601;
		case SPA_VIDEO_COLOR_RANGE_0_255: return k_EStreamColorspace_BT601_Full;
		default: break;
		}
		break;
	case SPA_VIDEO_COLOR_MATRIX_BT709:
		switch (video_info.color_range) {
		case SPA_VIDEO_COLOR_RANGE_16_235: return k_EStreamColorspace_BT709;
		case SPA_VIDEO_COLOR_RANGE_0_255: return k_EStreamColorspace_BT709_Full;
		default: break;
		}
		break;
	default: break;
	}
	return k_EStreamColorspace_Unknown;
}

static void stream_handle_add_buffer(void *user_data, struct pw_buffer *pw_buffer)
{
	struct pipewire_state *state = (struct pipewire_state *) user_data;

	struct pipewire_buffer *buffer = new pipewire_buffer();
	pw_buffer->user_data = buffer;
	buffer->buffer = pw_buffer;
	buffer->gamescope_info = state->gamescope_info;

	EStreamColorspace colorspace = spa_color_to_gamescope(state->video_info);
	uint32_t drmFormat = spa_format_to_drm(state->video_info.format);

	CVulkanTexture::createFlags imageFlags;
	imageFlags.bTransferDst = true;
	imageFlags.bStorage = true;
	if (SPA_FLAG_IS_SET(state->video_info.flags, SPA_VIDEO_FLAG_MODIFIER)) {
		imageFlags.exportModifiers = {&state->video_info.modifier, 1};
	}

	struct spa_buffer *spa_buffer = pw_buffer->buffer;
	for (uint32_t i = 0; i < spa_buffer->n_datas; i++) {
		struct spa_data *d = &spa_buffer->datas[i];

		if (SPA_FLAG_IS_SET(d->type, 1 << SPA_DATA_DmaBuf)) {
			d->type = SPA_DATA_DmaBuf;

			imageFlags.bExportable = true;
			if (imageFlags.exportModifiers.size() == 0) {
				// TODO: This should probably be `bMappable`. From the pipewire dma-buf documentation:
				// "[The producer can] choose DMA-BUF as the used buffer type even though no modifier is present, if it
				// can guarantee that the used buffer is mmapable."
				// If we use `bMappable`, it might no longer be device local, which could potentially hurt performance
				// for the more common use case of importing the fd instead of mmap-ing it. Use SPA_DATA_MemFd instead.
				// We do force a linear layout, because we won't be able to communicate any tiling or compression.
				imageFlags.bLinear = true;
			}
		} else if (SPA_FLAG_IS_SET(d->type, 1 << SPA_DATA_MemFd)) {
			d->type = SPA_DATA_MemFd;

			imageFlags.bExportable = true;
			imageFlags.bMappable = true;
		} else {
			pwr_log.errorf("unsupported data type");
			d->type = SPA_DATA_Invalid;
			return;
		}
	}

	pwr_log.debugf("creating texture (exportable: %d, mappable: %d)", imageFlags.bExportable, imageFlags.bMappable);
	buffer->texture = new CVulkanTexture();
	if (!buffer->texture->BInit(state->video_info.size.width, state->video_info.size.height, 1u, drmFormat, imageFlags)) {
		pwr_log.errorf("Failed to initialize pipewire texture");
		return;
	}
	buffer->texture->setStreamColorspace(colorspace);

	uint8_t *mappedData = buffer->texture->mappedData();
	const auto& dmabuf = buffer->texture->dmabuf();
	for (uint32_t i = 0; i < spa_buffer->n_datas; i++) {
		struct spa_data *d = &spa_buffer->datas[i];
		d->flags = SPA_DATA_FLAG_READABLE;
		if (imageFlags.bExportable && imageFlags.bMappable)
			d->flags |= SPA_DATA_FLAG_MAPPABLE;

		const auto& layout = buffer->texture->planeLayout(i);
		d->fd = dmabuf.fd[i];
		d->maxsize = layout.size;
		d->mapoffset = 0;
		d->data = mappedData;

		d->chunk->offset = layout.offset;
		d->chunk->size = layout.size;
		d->chunk->stride = layout.rowPitch;
	}
}

static void stream_handle_remove_buffer(void *data, struct pw_buffer *pw_buffer)
{
	struct pipewire_buffer *buffer = (struct pipewire_buffer *) pw_buffer->user_data;

	if (buffer == nullptr) {
		return;
	}
	pw_buffer->user_data = nullptr;
	buffer->buffer = nullptr;

	// We want to remove any references to this buffer
	struct pipewire_buffer *other = buffer;
	if (out_buffer.compare_exchange_strong(other, nullptr)) {
		buffer->copying = false;
	}
	other = buffer;
	if (in_buffer.compare_exchange_strong(other, nullptr)) {
		buffer->copying = false;
	}

	if (!buffer->copying) {
		destroy_buffer(buffer);
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

void pipewire_exit()
{
	struct pipewire_state *state = &pipewire_state;

	pwr_log.infof("exiting");

	pw_thread_loop_stop(state->loop);
	pw_loop_destroy_source(pw_thread_loop_get_loop(state->loop), state->nudge_source);
	close(state->nudge_fd);
	pw_stream_destroy(state->stream);
	pw_thread_loop_destroy(state->loop);
	pw_deinit();
}

bool pipewire_init()
{
	struct pipewire_state *state = &pipewire_state;

	pw_init(nullptr, nullptr);

	state->loop = pw_thread_loop_new("gamescope-pw", nullptr);
	if (!state->loop) {
		pwr_log.errorf("pw_thread_loop_new failed");
		return false;
	}
	pw_thread_loop_lock(state->loop);
	pw_thread_loop_start(state->loop);
	struct pw_loop *loop = pw_thread_loop_get_loop(state->loop);

	int nudgePipe[2];
	if (pipe2(nudgePipe, O_CLOEXEC | O_NONBLOCK) != 0) {
		pwr_log.errorf_errno("pipe2 failed");
		return false;
	}
	state->nudge_fd = nudgePipe[1];

	state->nudge_source = pw_loop_add_io(loop, nudgePipe[0], SPA_IO_IN, true, on_nudge, state);
	if (state->nudge_source == nullptr) {
		pwr_log.errorf("pw_loop_add_io failed");
		return false;
	}

	state->stream = pw_stream_new_simple(
		loop,
		"gamescope",
		pw_properties_new(
			PW_KEY_MEDIA_CLASS, "Video/Source",
			nullptr),
		&stream_events,
		state);
	if (!state->stream) {
		pwr_log.errorf("pw_stream_new_simple failed");
		return false;
	}

	uint8_t buf[4096];
	struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(buf, sizeof(buf));
	std::vector<const struct spa_pod *> format_params = build_format_params(&builder);

	enum pw_stream_flags flags = (enum pw_stream_flags)(PW_STREAM_FLAG_DRIVER | PW_STREAM_FLAG_ALLOC_BUFFERS);
	int ret = pw_stream_connect(state->stream, PW_DIRECTION_OUTPUT, PW_ID_ANY, flags, format_params.data(), format_params.size());
	if (ret != 0) {
		pwr_log.errorf("pw_stream_connect failed");
		return false;
	}

	pw_thread_loop_unlock(state->loop);
	return true;
}

uint32_t pipewire_get_stream_node_id()
{
	return pipewire_state.stream_node_id;
}

struct pipewire_buffer *pipewire_dequeue_buffer()
{
	struct pipewire_state *state = &pipewire_state;

	struct pipewire_buffer *buffer = out_buffer.exchange(nullptr);
	if (buffer == nullptr && state->streaming) {
		pw_thread_loop_lock(state->loop);
		buffer = dequeue_buffer(state);
		pw_thread_loop_unlock(state->loop);
	}
	return buffer;
}

struct pipewire_buffer *pipewire_push_buffer(struct pipewire_buffer *buffer)
{
	struct pipewire_state *state = &pipewire_state;

	buffer->pts = pw_stream_get_nsec(state->stream);

	struct pipewire_buffer *old = in_buffer.exchange(buffer);
	pipewire_nudge();
	// This will be `nullptr` if the pipewire thread is keeping up, otherwise the
	// compositor should reuse this old (previous) buffer
	return old;
}

void pipewire_nudge()
{
	struct pipewire_state *state = &pipewire_state;

	if (write(state->nudge_fd, "\n", 1) < 0)
		pwr_log.errorf_errno("nudge: write failed");
}
