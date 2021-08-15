#ifndef __RTK_FB_DRIVER_H__
#define __RTK_FB_DRIVER_H__

typedef struct venusfb_mach_info {
    void *dc_info;
} VENUSFB_MACH_INFO;

typedef struct FBDev_PARAM_BUF_ADDR
{
    unsigned int video_buf_Paddr;   
    unsigned int video_buf_count;
    unsigned int video_buf_size;   
    unsigned int width;
    unsigned int height;
    unsigned int misc_buf_Paddr;     
    unsigned int misc_buf_size;     
} FBDev_PARAM_BUF_ADDR;


#endif
