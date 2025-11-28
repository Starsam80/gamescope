#pragma once

#include <cstdint>
#include <spa/param/video/raw-utils.h>

enum {
    SPA_FORMAT_VIDEO_gamescope_focus_appid = 0x70001,
};

struct spa_gamescope
{
    uint64_t focus_appid;
};

static inline int
spa_format_video_raw_parse_with_gamescope(const struct spa_pod *format, struct spa_video_info_raw *info, spa_gamescope *gamescope_info)
{
    int ret = spa_format_video_raw_parse(format, info);
    if (ret < 0) {
        return ret;
    }
    return spa_pod_parse_object(format,
        SPA_TYPE_OBJECT_Format, NULL,
        SPA_FORMAT_VIDEO_gamescope_focus_appid, SPA_POD_OPT_Long(&gamescope_info->focus_appid));
}

static inline uint32_t spa_format_to_drm(const enum spa_video_format spa_format)
{
	switch (spa_format)
	{
		case SPA_VIDEO_FORMAT_BGRx: return DRM_FORMAT_XRGB8888;
		case SPA_VIDEO_FORMAT_NV12: return DRM_FORMAT_NV12;
		default: return DRM_FORMAT_INVALID;
	}
}
