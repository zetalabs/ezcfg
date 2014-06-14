# ------------------------------------------------------------------------------
# Copyright (C) 2008-2014 ezbox project
# ------------------------------------------------------------------------------

LIBEZCFG_CURRENT = 1
LIBEZCFG_REVISION = 0
LIBEZCFG_AGE = 0

if CONFIG_EZBOX_EZCFG_TEST
EXPORTED_SYMBOLS = exported_symbols_test
else
EXPORTED_SYMBOLS = exported_symbols
endif

SUBDIRS = .

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I$(top_builddir)/include \
	-I$(top_builddir)/api/include \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DDATADIR=\""$(datadir)"\" \
	-DEZCFG_DEBUG \
	-Wall -Werror

LDADD = libezcfg.la

libezcfgincludedir = $(includedir)/libezcfg

libezcfginclude_HEADERS = \
	$(top_builddir)/api/include/ezcfg-api.h

lib_LTLIBRARIES = libezcfg.la

libezcfg_la_CPPFLAGS = $(AM_CPPFLAGS) $(EZBOX_DISTRO_DEFINE) -I$(top_builddir)/api/include

libezcfg_la_LDFLAGS = \
	-version-info $(LIBEZCFG_CURRENT):$(LIBEZCFG_REVISION):$(LIBEZCFG_AGE) \
	-export-symbols $(top_builddir)/$(EXPORTED_SYMBOLS)

libezcfg_la_SOURCES = $(top_builddir)/src/common/meta_nvram.c
libezcfg_la_SOURCES += $(top_builddir)/src/common/ezcfg.c
libezcfg_la_SOURCES += $(top_builddir)/src/common/list.c
libezcfg_la_SOURCES += $(top_builddir)/src/common/link_list.c
libezcfg_la_SOURCES += $(top_builddir)/src/common/shm.c

# ezcfg data structures
libezcfg_la_SOURCES += $(top_builddir)/src/list/linked_list.c
libezcfg_la_SOURCES += $(top_builddir)/src/list/stack_list.c
libezcfg_la_SOURCES += $(top_builddir)/src/tree/avl_tree.c
libezcfg_la_SOURCES += $(top_builddir)/src/tree/binary_tree.c

# ezcfg Multi-Agents System model
libezcfg_la_SOURCES += $(top_builddir)/src/agent/agent.c
libezcfg_la_SOURCES += $(top_builddir)/src/agent/agent_core.c
libezcfg_la_SOURCES += $(top_builddir)/src/agent/agent_master.c
# libezcfg_la_SOURCES += $(top_builddir)/src/agent/agent_master_load_common_conf.c
# libezcfg_la_SOURCES += $(top_builddir)/src/agent/agent_master_load_socket_conf.c
libezcfg_la_SOURCES += $(top_builddir)/src/agent/agent_worker.c
libezcfg_la_SOURCES += $(top_builddir)/src/agent/agent_worker_json_http.c

# ezcfg Master/Worker thread model
libezcfg_la_SOURCES += $(top_builddir)/src/thread/thread.c
# libezcfg_la_SOURCES += $(top_builddir)/src/thread/master.c
#libezcfg_la_SOURCES += $(top_builddir)/src/thread/master_uevent.c
# libezcfg_la_SOURCES += $(top_builddir)/src/thread/master_load_common_conf.c
#libezcfg_la_SOURCES += $(top_builddir)/src/thread/master_load_socket_conf.c
#libezcfg_la_SOURCES += $(top_builddir)/src/thread/master_load_auth_conf.c
if CONFIG_EZBOX_SERVICE_OPENSSL
#libezcfg_la_SOURCES += $(top_builddir)/src/thread/master_load_ssl_conf.c
endif
if CONFIG_EZBOX_SERVICE_EZCFG_IGRSD
#libezcfg_la_SOURCES += $(top_builddir)/src/thread/master_load_igrs_conf.c
endif
if CONFIG_EZBOX_SERVICE_EZCFG_UPNPD
#libezcfg_la_SOURCES += $(top_builddir)/src/thread/master_upnp_ssdp.c
#libezcfg_la_SOURCES += $(top_builddir)/src/thread/master_load_upnp_conf.c
endif
# libezcfg_la_SOURCES += $(top_builddir)/src/thread/worker.c
# libezcfg_la_SOURCES += $(top_builddir)/src/thread/worker_ctrl.c
if CONFIG_EZBOX_SERVICE_EZCFG_HTTPD
# libezcfg_la_SOURCES += $(top_builddir)/src/thread/worker_http.c
endif
#libezcfg_la_SOURCES += $(top_builddir)/src/thread/worker_soap_http.c
if CONFIG_EZBOX_SERVICE_EZCFG_IGRSD
#libezcfg_la_SOURCES += $(top_builddir)/src/thread/worker_igrs.c
#libezcfg_la_SOURCES += $(top_builddir)/src/thread/worker_igrs_isdp.c
endif
#libezcfg_la_SOURCES += $(top_builddir)/src/thread/worker_uevent.c
if CONFIG_EZBOX_SERVICE_EZCFG_UPNPD
#libezcfg_la_SOURCES += $(top_builddir)/src/thread/worker_upnp_ssdp.c
#libezcfg_la_SOURCES += $(top_builddir)/src/thread/worker_upnp_http.c
#libezcfg_la_SOURCES += $(top_builddir)/src/thread/worker_upnp_gena.c
endif

# ezcfg args
libezcfg_la_SOURCES += $(top_builddir)/src/args/arg_nvram_socket.c
if CONFIG_EZBOX_SERVICE_OPENSSL
libezcfg_la_SOURCES += $(top_builddir)/src/args/arg_nvram_ssl.c
endif

# ezcfg utils
libezcfg_la_SOURCES += $(top_builddir)/src/util/util.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_adler32.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_base64.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_sha1.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_crc32.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_conf.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_file_get_line.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_file_extension.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_javascript_var_escaped.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_parse_args.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_socket_protocol.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_socket_domain.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_socket_type.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_socket_mcast.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_if_ipaddr.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_language.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_execute.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_rc.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_service_binding.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_text.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_tzdata.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_url.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_wan.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_mkdir.c
if CONFIG_EZBOX_SERVICE_EZCFG_UPNPD
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_upnp_role.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_upnp_device_type.c
libezcfg_la_SOURCES += $(top_builddir)/src/util/util_upnp_monitor.c
endif

# ezcfg control
#libezcfg_la_SOURCES += $(top_builddir)/src/ctrl/ctrl.c 
#libezcfg_la_SOURCES += $(top_builddir)/src/ctrl/ctrl_ipc.c 
if CONFIG_EZBOX_SERVICE_EZCFG_UPNPD
# libezcfg_la_SOURCES += $(top_builddir)/src/ctrl/ctrl_upnp.c
endif 
if CONFIG_EZBOX_SERVICE_EZCTP
# libezcfg_la_SOURCES += $(top_builddir)/src/ctrl/ctrl_ezctp.c
endif 

# ezcfg nvram
libezcfg_la_SOURCES += $(top_builddir)/src/nvram/nvram.c
#libezcfg_la_SOURCES += $(top_builddir)/src/nvram/nvram_defaults.c
#libezcfg_la_SOURCES += $(top_builddir)/src/nvram/nvram_validators.c
#libezcfg_la_SOURCES += $(top_builddir)/src/nvram/nvram_propagators.c

# ezctp support
if CONFIG_EZBOX_SERVICE_EZCTP
#libezcfg_la_SOURCES += $(top_builddir)/src/ezctp/ezctp.c
endif 

# ezcfg uevent
libezcfg_la_SOURCES += $(top_builddir)/src/uevent/uevent.c

# ezcfg authentication
libezcfg_la_SOURCES += $(top_builddir)/src/auth/auth.c

# ezcfg locale
libezcfg_la_SOURCES += $(top_builddir)/src/locale/locale.c

# ezcfg UUID
libezcfg_la_SOURCES += $(top_builddir)/src/uuid/uuid.c

# ezcfg socket
libezcfg_la_SOURCES += $(top_builddir)/src/socket/socket.c

# ezcfg HTTP/socket handler
libezcfg_la_SOURCES += $(top_builddir)/src/socket/socket_http.c

# ezcfg HTTP protocol
libezcfg_la_SOURCES += $(top_builddir)/src/http/http.c

if CONFIG_EZBOX_SERVICE_EZCFG_HTTPD
if CONFIG_EZBOX_SERVICE_EZCFG_HTTPD_SSI
# ezcfg HTTP SSI handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/http_ssi.c
endif

if CONFIG_EZBOX_SERVICE_EZCFG_HTTPD_WEBSOCKET
# ezcfg HTTP WEBSOCKET handling
libezcfg_la_SOURCES += $(top_builddir)/src/websocket/websocket.c
libezcfg_la_SOURCES += $(top_builddir)/src/websocket/http_websocket.c
endif

if CONFIG_EZBOX_SERVICE_EZCFG_HTTPD_CGI_NVRAM
# ezcfg HTTP nvram handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/http_nvram.c
endif

if CONFIG_EZBOX_SERVICE_EZCFG_HTTPD_CGI_INDEX
# ezcfg HTML/HTTP index handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/http_html_index.c
endif

if CONFIG_EZBOX_SERVICE_EZCFG_HTTPD_CGI_ADMIN
# ezcfg HTML/HTTP admin handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/http_html_admin.c

# ezcfg HTML/HTTP admin common head handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_common_head.c

# ezcfg HTML/HTTP admin head handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_head.c

# ezcfg HTML/HTTP admin foot handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_foot.c

# ezcfg HTML/HTTP admin button handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_button.c


# ezcfg HTML/HTTP admin menu handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_menu.c

# ezcfg HTML/HTTP admin menu status handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_menu_status.c

# ezcfg HTML/HTTP admin menu setup handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_menu_setup.c

# ezcfg HTML/HTTP admin menu management handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_menu_management.c


# ezcfg HTML/HTTP admin layout_css handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_layout_css.c

# ezcfg HTML/HTTP admin status_system handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_status_system.c

# ezcfg HTML/HTTP admin status_lan handling
if CONFIG_EZBOX_LAN_NIC
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_status_lan.c
endif

# ezcfg HTML/HTTP admin view_dhcp_client_table handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_view_dhcp_client_table.c

# ezcfg HTML/HTTP admin status_wan handling
if CONFIG_EZBOX_WAN_NIC
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_status_wan.c
endif

# ezcfg HTML/HTTP admin setup_system handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_setup_system.c

# ezcfg HTML/HTTP admin setup_lan handling
if CONFIG_EZBOX_LAN_NIC
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_setup_lan.c
endif

# ezcfg HTML/HTTP admin setup_wan handling
if CONFIG_EZBOX_WAN_NIC
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_setup_wan.c
endif

# ezcfg HTML/HTTP admin management_authz handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_management_authz.c

# ezcfg HTML/HTTP admin management_default handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_management_default.c

# ezcfg HTML/HTTP admin management_upgrade handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_management_upgrade.c

if CONFIG_EZBOX_SERVICE_EMC2
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_menu_cnc.c
# ezcfg HTML/HTTP admin cnc_setup handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_cnc_setup.c
# ezcfg HTML/HTTP admin cnc_default handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_cnc_default.c
# ezcfg HTML/HTTP admin cnc_latency handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/admin/http_html_admin_cnc_latency.c
endif # end of CONFIG_EZBOX_SERVICE_EMC2
endif # end of CONFIG_EZBOX_SERVICE_EZCFG_HTTPD_CGI_ADMIN

if CONFIG_EZBOX_SERVICE_EZCFG_HTTPD_CGI_APPLY
# ezcfg HTML/HTTP apply handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/http_html_apply.c

# ezcfg HTML/HTTP apply common head handling
libezcfg_la_SOURCES += $(top_builddir)/src/http/apply/http_html_apply_common_head.c

endif # end of CONFIG_EZBOX_SERVICE_EZCFG_HTTPD_CGI_APPLY
endif # end of CONFIG_EZBOX_SERVICE_EZCFG_HTTPD

# ezcfg XML doc
libezcfg_la_SOURCES += $(top_builddir)/src/xml/xml.c

# ezcfg HTML handling
libezcfg_la_SOURCES += $(top_builddir)/src/html/html.c

# ezcfg CSS handling
libezcfg_la_SOURCES += $(top_builddir)/src/css/css.c

# ezcfg SSI handling
libezcfg_la_SOURCES += $(top_builddir)/src/ssi/ssi.c

# ezcfg JSON parser
libezcfg_la_SOURCES += $(top_builddir)/src/json/json.c

# ezcfg JSON over HTTP
libezcfg_la_SOURCES += $(top_builddir)/src/json/json_http.c

# ezcfg NVRAM on JSON over HTTP
libezcfg_la_SOURCES += $(top_builddir)/src/json/json_http_nvram.c

if CONFIG_EZBOX_SERVICE_OPENSSL
# ezcfg SSL handling
libezcfg_la_SOURCES += $(top_builddir)/src/ssl/ssl.c
endif

# ezcfg SOAP protocol
libezcfg_la_SOURCES += $(top_builddir)/src/soap/soap.c

# ezcfg SOAP-HTTP binding
libezcfg_la_SOURCES += $(top_builddir)/src/soap/soap_http.c

# ezcfg NVRAM/SOAP-HTTP binding
libezcfg_la_SOURCES += $(top_builddir)/src/soap/soap_http_nvram.c

# ezcfg IGRS protocol
libezcfg_la_SOURCES += $(top_builddir)/src/igrs/igrs.c
libezcfg_la_SOURCES += $(top_builddir)/src/igrs/igrs_create_session.c
libezcfg_la_SOURCES += $(top_builddir)/src/igrs/igrs_invoke_service.c

if CONFIG_EZBOX_SERVICE_EZCFG_IGRSD
# ezcfg ISDP protocol
libezcfg_la_SOURCES += $(top_builddir)/src/igrs/igrs_isdp.c
endif

if CONFIG_EZBOX_SERVICE_EZCFG_UPNPD
# ezcfg UPNP protocol
libezcfg_la_SOURCES += $(top_builddir)/src/upnp/upnp.c
# ezcfg SSDP protocol
libezcfg_la_SOURCES += $(top_builddir)/src/upnp/upnp_ssdp.c
libezcfg_la_SOURCES += $(top_builddir)/src/upnp/upnp_gena.c
endif

# ezcfg API wrap
libezcfg_la_SOURCES += $(top_builddir)/api/src/api-common.c
libezcfg_la_SOURCES += $(top_builddir)/api/src/api-util.c
libezcfg_la_SOURCES += $(top_builddir)/api/src/api-agent.c
#libezcfg_la_SOURCES += $(top_builddir)/api/src/api-master.c
#libezcfg_la_SOURCES += $(top_builddir)/api/src/api-ctrl.c
#libezcfg_la_SOURCES += $(top_builddir)/api/src/api-ipc.c
#libezcfg_la_SOURCES += $(top_builddir)/api/src/api-arg_nvram_socket.c
#if CONFIG_EZBOX_SERVICE_OPENSSL
#libezcfg_la_SOURCES += $(top_builddir)/api/src/api-arg_nvram_ssl.c
#endif
libezcfg_la_SOURCES += $(top_builddir)/api/src/api-nvram.c
#libezcfg_la_SOURCES += $(top_builddir)/api/src/api-rc.c
#libezcfg_la_SOURCES += $(top_builddir)/api/src/api-uuid.c
#if CONFIG_EZBOX_SERVICE_EZCFG_UPNPD
#libezcfg_la_SOURCES += $(top_builddir)/api/src/api-upnp.c
#endif
#if CONFIG_EZBOX_SERVICE_EZCTP
#libezcfg_la_SOURCES += $(top_builddir)/api/src/api-ezctp.c
#endif 
#libezcfg_la_SOURCES += $(top_builddir)/api/src/api-ubootenv.c
#libezcfg_la_SOURCES += $(top_builddir)/api/src/api-firmware.c