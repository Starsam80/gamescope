#pragma once

#include <memory>

class CVulkanTexture;

void pipewire_init(void);
uint32_t pipewire_get_node_id(void);
bool pipewire_is_streaming(void);
void pipewire_copy_texture(const std::shared_ptr<CVulkanTexture>& compositeImage, bool queue);
void pipewire_resize_output(uint32_t width, uint32_t height);
