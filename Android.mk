LOCAL_PATH:= $(call my-dir)

#####################
# libezcfg
#####################
include $(CLEAR_VARS)

# We need to build this for both the device (as a shared library)
# and the host (as a static library for tools to use).


LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/libezcfg/include \
	$(LOCAL_PATH)/libezcfg/api/include \


# get from ezcfg/libezcfg/lib/Makefile.am
###################
# common part
###################
# ezcfg common
LOCAL_SRC_FILES := \
        libezcfg/src/common/ezcfg.c \
        libezcfg/src/common/nv_pair.c \
        libezcfg/src/common/linked_list.c \
        libezcfg/src/common/stack_list.c \
        libezcfg/src/common/binary_tree.c \
        libezcfg/src/common/json.c \
        libezcfg/src/common/meta_nvram.c \
        libezcfg/src/common/nvram.c \
        libezcfg/src/basic/nv_pair/nv_pair.c \
        libezcfg/src/basic/linked_list/linked_list.c \
        libezcfg/src/basic/stack_list/stack_list.c \
        libezcfg/src/basic/binary_tree/binary_tree.c \
        libezcfg/src/basic/nv_linked_list/nv_linked_list.c \
        libezcfg/src/basic/socket/socket.c \
        libezcfg/src/basic/socket/socket_http.c \
        libezcfg/src/basic/auth/auth.c \
        libezcfg/src/basic/http/http.c \
        libezcfg/src/basic/json/json.c \
        libezcfg/src/basic/json/json_nvram.c \
        libezcfg/src/basic/thread/thread.c \
        libezcfg/src/basic/process/process.c \
        libezcfg/src/composite/nv_json_http/nv_json_http.c \
        libezcfg/src/composite/socket_agent/socket_agent.c \
        libezcfg/src/composite/socket_agent/socket_agent_master_thread.c \
        libezcfg/src/composite/socket_agent/socket_agent_worker_thread.c \
        libezcfg/src/composite/socket_agent/socket_agent_worker_thread_http.c \
        libezcfg/src/composite/socket_agent/socket_agent_worker_thread_nv_json_http.c \
        libezcfg/src/composite/socket_agent/socket_agent_env_thread.c \
        libezcfg/src/util/util.c \
        libezcfg/src/util/util_adler32.c \
        libezcfg/src/util/util_base64.c \
        libezcfg/src/util/util_sha1.c \
        libezcfg/src/util/util_crc32.c \
        libezcfg/src/util/util_conf.c \
        libezcfg/src/util/util_file_get_line.c \
        libezcfg/src/util/util_file_extension.c \
        libezcfg/src/util/util_javascript_var_escaped.c \
        libezcfg/src/util/util_parse_args.c \
        libezcfg/src/util/util_socket_domain.c \
        libezcfg/src/util/util_socket_type.c \
        libezcfg/src/util/util_socket_protocol.c \
        libezcfg/src/util/util_socket_role.c \
        libezcfg/src/util/util_socket_mcast.c \
        libezcfg/src/util/util_if_ipaddr.c \
        libezcfg/src/util/util_language.c \
        libezcfg/src/util/util_execute.c \
        libezcfg/src/util/util_service_binding.c \
        libezcfg/src/util/util_text.c \
        libezcfg/src/util/util_tzdata.c \
        libezcfg/src/util/util_url.c \
        libezcfg/src/util/util_wan.c \
        libezcfg/src/util/util_mkdir.c \
        libezcfg/src/util/util_snprintf_ns_name.c \
        libezcfg/src/util/util_proc_check_pid.c \
        libezcfg/api/src/api-common.c \
        libezcfg/api/src/api-agent.c \
        libezcfg/api/src/api-nvram.c \


LOCAL_CFLAGS += -DCONFIG_EZCFG_EZBOX_DISTRO_FUXI
LOCAL_CFLAGS += -DSYSCONFDIR=\"/data/ezcfg/etc\"
LOCAL_CFLAGS += -DDATADIR=\"/data/ezcfg/data\"
LOCAL_CFLAGS += -DEZCFG_DEBUG
LOCAL_CFLAGS += -DANDROID_BUILD
LOCAL_CFLAGS += -Wall
#LOCAL_CFLAGS += -Werror


LOCAL_C_FLAGS += -DPTHREAD_MUTEX_RECURSIVE=PTHREAD_MUTEX_RECURSIVE

LOCAL_MODULE:= libezcfg

#turn off warnings since we cannot fix them
#LOCAL_CFLAGS += -w

include $(BUILD_SHARED_LIBRARY)
 

#####################
# libezcd
#####################
include $(CLEAR_VARS)

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/ezcd/include \
	$(LOCAL_PATH)/libezcfg/include \
	$(LOCAL_PATH)/libezcfg/api/include \


# get from ezcd/lib/Makefile.am
###################
# common part
###################
# ezcfg common
LOCAL_SRC_FILES := \
        ezcd/src/utils/utils_crc32.c \
        ezcd/src/utils/utils_file_get_keyword.c \
        ezcd/src/utils/utils_get_kernel_init.c \
        ezcd/src/utils/utils_get_kernel_modules.c \
        ezcd/src/utils/utils_get_kernel_version.c \
        ezcd/src/utils/utils_get_mem_size.c \
        ezcd/src/utils/utils_handle_kernel_module.c \
        ezcd/src/utils/utils_make_dirs.c \
        ezcd/src/utils/utils_clean_dirs.c \
        ezcd/src/utils/utils_mount_partition.c \
        ezcd/src/utils/utils_swap_partition.c \
        ezcd/src/utils/utils_get_bootcfg_keyword.c \
        ezcd/src/utils/utils_get_device_info.c \
        ezcd/src/utils/utils_init_ezcfg_api.c \
        ezcd/src/utils/utils_file_get_line.c \
        ezcd/src/utils/utils_file_print_line.c \
        ezcd/src/utils/utils_file_get_content.c \
        ezcd/src/utils/utils_find_pid_by_name.c \
        ezcd/src/utils/utils_device_open.c \
        ezcd/src/utils/utils_parse_args.c \
        ezcd/src/utils/utils_read_write.c \
        ezcd/src/utils/utils_execute.c \
        ezcd/src/utils/utils_mkdir.c \
        ezcd/src/utils/utils_system.c \
        ezcd/src/utils/utils_udev_trigger_pop.c \


LOCAL_CFLAGS += -DCONFIG_EZCFG_EZBOX_DISTRO_FUXI
LOCAL_CFLAGS += -DSYSCONFDIR=\"/data/ezcfg/etc\"
LOCAL_CFLAGS += -DDATADIR=\"/data/ezcfg/data\"
LOCAL_CFLAGS += -DEZCFG_DEBUG
LOCAL_CFLAGS += -DANDROID_BUILD
LOCAL_CFLAGS += -Wall
#LOCAL_CFLAGS += -Werror


LOCAL_C_FLAGS += -DPTHREAD_MUTEX_RECURSIVE=PTHREAD_MUTEX_RECURSIVE

LOCAL_MODULE:= libezcd
LOCAL_SHARED_LIBRARIES := libezcfg

#turn off warnings since we cannot fix them
#LOCAL_CFLAGS += -w

include $(BUILD_SHARED_LIBRARY)
 

#####################
# ezcd
#####################
include $(CLEAR_VARS)

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/ezcd/include \
	$(LOCAL_PATH)/libezcfg/include \
	$(LOCAL_PATH)/libezcfg/api/include \

LOCAL_SRC_FILES := \
        ezcd/src/main.c \
        ezcd/src/agent_env.c \
        ezcd/src/eznvc.c \
        ezcd/src/eznvdump.c


LOCAL_CFLAGS += -DCONFIG_EZCFG_EZBOX_DISTRO_FUXI
LOCAL_CFLAGS += -DSYSCONFDIR=\"/data/ezcfg/etc\"
LOCAL_CFLAGS += -DDATADIR=\"/data/ezcfg/data\"
LOCAL_CFLAGS += -DEZCFG_DEBUG
LOCAL_CFLAGS += -DANDROID_BUILD
LOCAL_CFLAGS += -Wall
#LOCAL_CFLAGS += -Werror


LOCAL_C_FLAGS += -DPTHREAD_MUTEX_RECURSIVE=PTHREAD_MUTEX_RECURSIVE

LOCAL_MODULE := ezcfgd
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := libezcfg libezcd

include $(BUILD_EXECUTABLE)

TOOLS := \
        ezcd \
        eznvc \
        eznvdump

ALL_TOOLS = $(TOOLS)

# Make #!/system/bin/ezcfgd launchers for each tool.
#
SYMLINKS := $(addprefix $(TARGET_OUT)/bin/,$(ALL_TOOLS))
$(SYMLINKS): EZCFGD_BINARY := $(LOCAL_MODULE)
$(SYMLINKS): $(LOCAL_INSTALLED_MODULE) $(LOCAL_PATH)/Android.mk
	@echo "Symlink: $@ -> $(EZCFGD_BINARY)"
	@mkdir -p $(dir $@)
	@rm -rf $@
	$(hide) ln -sf $(EZCFGD_BINARY) $@

ALL_DEFAULT_INSTALLED_MODULES += $(SYMLINKS)

# We need this so that the installed files could be picked up based on the
# local module name
ALL_MODULES.$(LOCAL_MODULE).INSTALLED := \
    $(ALL_MODULES.$(LOCAL_MODULE).INSTALLED) $(SYMLINKS)

