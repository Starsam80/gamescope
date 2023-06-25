#pragma once

#include <memory>
#include <pipewire/pipewire.h>
#include <spa/param/video/format-utils.h>

class CVulkanTexture;

struct pipewire_state {
	pipewire_state();
	~pipewire_state();

	struct pw_thread_loop *thread;
	struct pw_context *context;
	struct pw_core *core;

	struct pw_stream *stream;
	uint32_t stream_node_id = SPA_ID_INVALID;
	bool streaming;
	struct spa_video_info_raw video_info;
	struct spa_rectangle output_size;
	bool dmabuf;
	int shm_stride;
	uint64_t seq;
};

bool init_pipewire(void);
uint32_t get_pipewire_stream_node_id(void);
bool pipewire_is_streaming(void);
void pipewire_copy_texture(const std::shared_ptr<CVulkanTexture>& compositeImage, bool queue);
void nudge_pipewire(void);
void pipewire_resize_output(uint32_t width, uint32_t height);
