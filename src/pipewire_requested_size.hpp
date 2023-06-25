#pragma once

enum {
	SPA_FORMAT_VIDEO_requested_size = 0x70000
};

enum {
	SPA_META_requested_size_scale = 0x70000
};

static inline int
spa_format_video_raw_parse_with_requested_size(const struct spa_pod *format, struct spa_video_info_raw *info, spa_rectangle *requested_size)
{
	int ret = spa_format_video_raw_parse(format, info);
	if (ret < 0) {
		return ret;
	}
	return spa_pod_parse_object(format,
		SPA_TYPE_OBJECT_Format, NULL,
		SPA_FORMAT_VIDEO_requested_size, SPA_POD_OPT_Rectangle(requested_size));
}

