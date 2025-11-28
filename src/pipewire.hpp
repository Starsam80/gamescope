#pragma once

#include <memory>

#include "rendervulkan.hpp"
#include "pipewire_gamescope.hpp"

struct pw_buffer;

/**
 * PipeWire buffers are allocated by the PipeWire thread, and are temporarily
 * shared with the steamcompmgr thread (via pipewire_dequeue_buffer and
 * pipewire_push_buffer) for copying.
 */
struct pipewire_buffer {
	struct spa_gamescope gamescope_info;
	gamescope::OwningRc<CVulkanTexture> texture;
	uint64_t pts;

	// The following fields are not thread-safe

	// The PipeWire buffer, or nullptr if it's been destroyed.
	std::atomic<struct pw_buffer *> buffer;
	bool IsStale() const 
	{
		return buffer == nullptr;
	}
	// We pass the buffer to the steamcompmgr thread for copying. This is set
	// to true if the buffer is currently owned by the steamcompmgr thread.
	bool copying;
};

bool pipewire_init();
void pipewire_exit();
uint32_t pipewire_get_stream_node_id();
struct pipewire_buffer *pipewire_dequeue_buffer();
void pipewire_destroy_buffer(struct pipewire_buffer *buffer);
struct pipewire_buffer *pipewire_push_buffer(struct pipewire_buffer *buffer);
void pipewire_nudge();
