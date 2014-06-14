# ------------------------------------------------------------------------------
# Copyright (C) 2008-2013 ezbox project
# ------------------------------------------------------------------------------

SUBDIRS = .

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I$(top_builddir)/include \
        -DSYSCONFDIR=\""$(sysconfdir)"\" \
        -DDATADIR="$(datadir)" \
        -DEZCFG_DEBUG \
        -Wall -Werror

AM_LDFLAGS = -L. -ldl

# ezcd depends on libezcfg
# LIBS += -lezcfg
ezcd_DEPENDENCIES = libezcfg.so libezcd.so $(RCSO_SO) $(RCSO_EXE)
ezcd_DEPENDENCIES += $(AGENT_ENV_SO) $(AGENT_ENV_EXE)
if CONFIG_EZBOX_EZCFG_SYSUP
ezcd_DEPENDENCIES += sysup
endif
ezcd_CPPFLAGS = $(AM_CPPFLAGS) $(EZBOX_DISTRO_DEFINE) $(LIBEZCFG_INCLUDE) $(LIBEZCFG_API_INCLUDE)
#ezcd_LDADD = $(LDADD) -L$(top_builddir)/lib/.libs -lezcd
ezcd_LDFLAGS = $(AM_LDFLAGS) -lezcfg -lezcd
ezcd_LDFLAGS += -Wl,-Map,ezcd.map

sbin_PROGRAMS =	ezcd


# basic functions
ezcd_SOURCES = $(top_builddir)/src/main.c
ezcd_SOURCES += $(top_builddir)/src/agent_env.c
#ezcd_SOURCES += $(top_builddir)/src/preinit.c
#ezcd_SOURCES += $(top_builddir)/src/init.c
#ezcd_SOURCES += $(top_builddir)/src/ezcd.c
#ezcd_SOURCES += $(top_builddir)/src/ezcm.c
#ezcd_SOURCES += $(top_builddir)/src/nvram.c
#ezcd_SOURCES += $(top_builddir)/src/rc.c
ezcd_SOURCES += $(top_builddir)/src/shelld.c
#if CONFIG_EZBOX_SERVICE_EZCFG_IGRSD
#ezcd_SOURCES += $(top_builddir)/src/igrs_monitor.c
#endif
#if CONFIG_EZBOX_SERVICE_EZCFG_UPNPD
#ezcd_SOURCES += $(top_builddir)/src/upnp_monitor.c
#endif

#ezcd_SOURCES += $(top_builddir)/src/rc/rc_func.c
#ezcd_SOURCES += $(top_builddir)/src/rc/rc_debug.c

# ubootenv support
#ezcd_SOURCES += $(top_builddir)/src/ubootenv.c

# udhcpc script support
if CONFIG_EZBOX_WAN_NIC
#ezcd_SOURCES += $(top_builddir)/src/udhcpc_script.c
endif

# upgrade firmware support
#ezcd_SOURCES += $(top_builddir)/src/upfw.c

libezcfg.so: $(LIBEZCFG_LIB)
	-rm -f libezcfg.so
	$(LN_S) $(LIBEZCFG_LIB)/libezcfg.so libezcfg.so

libezcd.so: $(top_builddir)/lib/.libs/libezcd.so
	-rm -f libezcd.so
	$(LN_S) $(top_builddir)/lib/.libs/libezcd.so libezcd.so

sysup: $(top_builddir)/src/sysup.c
	$(CC) -static -o $@ $<

###############################
# rcso
###############################
RCSO_CFLAGS = -Wall -Werror -rdynamic -fPIC
RCSO_CFLAGS += $(ezcd_CPPFLAGS)
RCSO_SRC = rc_agent.c
#RCSO_SRC += rc_exec.c
#RCSO_SRC += rc_data_partition.c
#RCSO_SRC += rc_env.c
#RCSO_SRC += rc_ezcfg_httpd.c
if CONFIG_EZBOX_SERVICE_EZCFG_IGRSD
#RCSO_SRC += rc_ezcfg_igrsd.c
endif
if CONFIG_EZBOX_SERVICE_EZCFG_UPNPD
#RCSO_SRC += rc_ezcfg_upnpd.c
#RCSO_SRC += rc_upnp_monitor.c
endif
#RCSO_SRC += rc_resolv_conf.c
#RCSO_SRC += rc_init.c
#RCSO_SRC += rc_ldconfig.c
if CONFIG_EZBOX_SERVICE_WPA_SUPPLICANT
#RCSO_SRC += rc_wpa_supplicant.c
endif

# telnet service
if CONFIG_EZBOX_SERVICE_TELNETD
#RCSO_SRC += rc_telnetd.c
endif
# dhcp/dns service
if CONFIG_EZBOX_SERVICE_DNSMASQ
#RCSO_SRC += rc_dnsmasq.c
endif
# DHIS client service
if CONFIG_EZBOX_SERVICE_DHID
#RCSO_SRC += rc_dhid.c
endif
# DHIS server service
if CONFIG_EZBOX_SERVICE_DHISD
#RCSO_SRC += rc_dhisd.c
endif
# ezctp service
if CONFIG_EZBOX_SERVICE_EZCTP
#RCSO_SRC += rc_ezctp.c
endif
# dillo web browser service
if CONFIG_EZBOX_SERVICE_DILLO
#RCSO_SRC += rc_dillo.c
endif
# EMC2 Enhanced Machine Controller service
if CONFIG_EZBOX_SERVICE_EMC2
#RCSO_SRC += rc_realtime.c
#RCSO_SRC += rc_emc2.c
#RCSO_SRC += rc_emc2_latency_test.c
endif
# coova-chilli Hotspot Manager
if CONFIG_EZBOX_SERVICE_COOVA_CHILLI
#RCSO_SRC += rc_coova_chilli.c
endif
# LXC Linux Container service
if CONFIG_EZBOX_SERVICE_LXC
#RCSO_SRC += rc_lxc.c
endif
# PPPoE server service
if CONFIG_EZBOX_SERVICE_PPPOE_SERVER
#RCSO_SRC += rc_pppoe_server.c
endif
# FreeRADIUS2 server service
if CONFIG_EZBOX_SERVICE_FREERADIUS2_SERVER
#RCSO_SRC += rc_freeradius2_server.c
endif

RCSO_SO = $(subst .c,.so,$(RCSO_SRC))
RCSO_EXE = $(subst .c,.exe,$(RCSO_SRC))

###############################
# agent environment
###############################
AGENT_ENV_SRC = env_action_base_files.c
AGENT_ENV_SRC += env_action_bootstrap.c
if CONFIG_EZBOX_EZCFG_CGROUP
AGENT_ENV_SRC += env_action_cgroup.c
endif
if CONFIG_EZBOX_BR_LAN_NIC
AGENT_ENV_SRC += env_action_br_lan_if.c
endif
AGENT_ENV_SRC += env_action_swap_partition.c
AGENT_ENV_SRC += env_action_data_storage.c
AGENT_ENV_SRC += env_action_data_partition.c
# LUKS/dm-crypt for data partition service
if CONFIG_EZBOX_SERVICE_DMCRYPT_DATA_PARTITION
AGENT_ENV_SRC += env_action_dmcrypt_data_partition.c
endif
# network
if CONFIG_EZBOX_ETH_LAN_NIC
AGENT_ENV_SRC += env_action_eth_lan_if.c
endif
AGENT_ENV_SRC += env_action_ezcd.c
AGENT_ENV_SRC += env_action_ezcm.c
if CONFIG_EZBOX_SERVICE_IPTABLES
AGENT_ENV_SRC += env_action_iptables.c
endif
# klogd service
if CONFIG_EZBOX_SERVICE_KLOGD
AGENT_ENV_SRC += env_action_klogd.c
endif
if CONFIG_EZBOX_LAN_NIC
AGENT_ENV_SRC += env_action_lan.c
endif
AGENT_ENV_SRC += env_action_load_modules.c
AGENT_ENV_SRC += env_action_login.c
AGENT_ENV_SRC += env_action_loopback.c
AGENT_ENV_SRC += env_action_mount_system_fs.c
AGENT_ENV_SRC += env_action_netbase.c
AGENT_ENV_SRC += env_action_nvram.c
if CONFIG_EZBOX_SERVICE_OPENSSL
AGENT_ENV_SRC += env_action_openssl.c
endif
AGENT_ENV_SRC += env_action_overlay_rootfs.c
# PPP service
if CONFIG_EZBOX_SERVICE_PPP
AGENT_ENV_SRC += env_action_ppp_chap_secrets.c
AGENT_ENV_SRC += env_action_ppp_pap_secrets.c
endif
# PPP RP-PPPoE service
if CONFIG_EZBOX_SERVICE_PPP_RP_PPPOE
AGENT_ENV_SRC += env_action_ppp_rp_pppoe.c
endif
AGENT_ENV_SRC += env_action_preboot.c
AGENT_ENV_SRC += env_action_shelld.c
AGENT_ENV_SRC += env_action_state.c
# syslogd service
if CONFIG_EZBOX_SERVICE_SYSLOGD
AGENT_ENV_SRC += env_action_syslogd.c
endif
AGENT_ENV_SRC += env_action_system.c
AGENT_ENV_SRC += env_action_udev_pop_nodes.c
if CONFIG_EZBOX_ETH_WAN_NIC
AGENT_ENV_SRC += env_action_eth_wan_if.c
endif
if CONFIG_EZBOX_WAN_NIC
AGENT_ENV_SRC += env_action_wan.c
AGENT_ENV_SRC += env_action_wan_if.c
endif
if CONFIG_EZBOX_WIFI_LAN_NIC
AGENT_ENV_SRC += env_action_wifi_lan_if.c
endif

AGENT_ENV_SO = $(subst .c,.so,$(AGENT_ENV_SRC))
AGENT_ENV_EXE = $(subst .c,.exe,$(AGENT_ENV_SRC))


%.so : $(top_builddir)/src/rcso/%.c
	$(CC) $(RCSO_CFLAGS) -Wl,-Map,$@.map -L. -lezcd -ldl -shared $< -o $@

%.exe : $(top_builddir)/src/rcso/%.c
	$(CC) $(RCSO_CFLAGS) $(CFLAGS) $(LDFLAGS) $(LIBS) -D_EXEC_ $< -o $@ -L. -lezcd -lezcfg -ldl

clean-local: clean-local-check
clean-local-check:
	-rm -rf *.so *.exe

.PHONY: clean-local-check
