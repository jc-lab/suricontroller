/* Thin glue between the Rust suritap plugin and Suricata internals that
 * Rust cannot reach through FFI: static inline functions, macros and
 * fields of large configuration-dependent structs (Packet, ThreadVars,
 * TmModule). It contains no logic of its own. */

#include "suricata-common.h"
#include "suricata-plugin.h"
#include "suricata.h"
#include "action-globals.h"
#include "decode.h"
#include "detect.h"
#include "flow.h"
#include "packet.h"
#include "runmodes.h"
#include "threadvars.h"
#include "tm-modules.h"
#include "tm-threads.h"
#include "tm-threads-common.h"
#include "tmqh-packetpool.h"
#include "util-datalink.h"
#include "util-debug.h"
#include "util-device.h"
#include "util-time.h"
#include "util-affinity.h"

/* Mirrors engine::AlertInfo / engine::Outcome in Rust. */
typedef struct SuritapAlert {
    uint32_t sid, gid, rev;
    uint8_t action, pad[3];
} SuritapAlert;

typedef struct SuritapOutcome {
    uint8_t action;
    uint8_t drop_reason;
    uint8_t reason;
    uint8_t n_alerts;
    uint16_t alert_total;
    uint8_t bypass;
    uint8_t failed;
    SuritapAlert alerts[8];
} SuritapOutcome;

typedef struct SuritapCallbacks {
    TmEcode (*thread_init)(ThreadVars *, const void *, void **);
    TmEcode (*loop)(ThreadVars *, void *, void *);
    TmEcode (*break_loop)(ThreadVars *, void *);
    TmEcode (*thread_deinit)(ThreadVars *, void *);
    void (*exit_stats)(ThreadVars *, void *);
} SuritapCallbacks;

/* suritap::proto::Reason */
enum { SURITAP_REASON_RULE = 1, SURITAP_REASON_POLICY = 2, SURITAP_REASON_FLOW = 3 };

const char *suritap_suricata_version(void)
{
    return PACKAGE_VERSION;
}

void suritap_log(int level, const char *msg)
{
    SCLog(level, "suritap", "suritap", 0, "suritap", "%s", msg);
}

int suritap_log_level_error(void) { return SC_LOG_ERROR; }
int suritap_log_level_warning(void) { return SC_LOG_WARNING; }
int suritap_log_level_notice(void) { return SC_LOG_NOTICE; }
int suritap_log_level_info(void) { return SC_LOG_INFO; }
int suritap_log_level_debug(void) { return SC_LOG_DEBUG; }

int suritap_register_capture(
        const char *name, void (*init)(const char *, int, int, int), const char *(*default_mode)(void))
{
    SCCapturePlugin *plugin = SCCalloc(1, sizeof(*plugin));
    if (plugin == NULL) {
        return -1;
    }
    plugin->name = (char *)name;
    plugin->Init = init;
    plugin->GetDefaultMode = default_mode;
    return SCPluginRegisterCapture(plugin);
}

/* --- decode module: plain raw IPv4/IPv6 --- */

static TmEcode SuritapDecodeThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    DecodeThreadVars *dtv = DecodeThreadVarsAlloc(tv);
    if (dtv == NULL) {
        return TM_ECODE_FAILED;
    }
    DecodeRegisterPerfCounters(dtv, tv);
    *data = dtv;
    return TM_ECODE_OK;
}

static TmEcode SuritapDecodeThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL) {
        DecodeThreadVarsFree(tv, data);
    }
    return TM_ECODE_OK;
}

static TmEcode SuritapDecode(ThreadVars *tv, Packet *p, void *data)
{
    DecodeThreadVars *dtv = data;
    DecodeUpdatePacketCounters(tv, dtv, p);
    DecodeLinkLayer(tv, dtv, p->datalink, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
    PacketDecodeFinalize(tv, dtv, p);
    return TM_ECODE_OK;
}

void suritap_register_modules(int receive_slot, int decode_slot, const SuritapCallbacks *cb)
{
    tmm_modules[receive_slot].name = "ReceiveSuritap";
    tmm_modules[receive_slot].ThreadInit = cb->thread_init;
    tmm_modules[receive_slot].Func = NULL;
    tmm_modules[receive_slot].PktAcqLoop = cb->loop;
    tmm_modules[receive_slot].PktAcqBreakLoop = cb->break_loop;
    tmm_modules[receive_slot].ThreadExitPrintStats = cb->exit_stats;
    tmm_modules[receive_slot].ThreadDeinit = cb->thread_deinit;
    tmm_modules[receive_slot].cap_flags = 0;
    tmm_modules[receive_slot].flags = TM_FLAG_RECEIVE_TM;

    tmm_modules[decode_slot].name = "DecodeSuritap";
    tmm_modules[decode_slot].ThreadInit = SuritapDecodeThreadInit;
    tmm_modules[decode_slot].Func = SuritapDecode;
    tmm_modules[decode_slot].ThreadExitPrintStats = NULL;
    tmm_modules[decode_slot].ThreadDeinit = SuritapDecodeThreadDeinit;
    tmm_modules[decode_slot].cap_flags = 0;
    tmm_modules[decode_slot].flags = TM_FLAG_DECODE_TM;
}

/* Worker thread: receive -> decode -> flow worker. RespondReject is left
 * out on purpose: there is no wire to inject TCP resets or ICMP into;
 * reject rules are reported as drops in the verdict instead. */
int suritap_spawn_worker(const char *name, const char *iface, void *initdata)
{
    ThreadVars *tv = TmThreadCreatePacketHandler(
            name, "packetpool", "packetpool", "packetpool", "packetpool", "pktacqloop");
    if (tv == NULL) {
        return -1;
    }
    tv->printable_name = SCStrdup(name);
    tv->iface_name = SCStrdup(iface);
    TmModule *m = TmModuleGetByName("ReceiveSuritap");
    if (m == NULL) {
        return -1;
    }
    TmSlotSetFuncAppend(tv, m, initdata);
    if ((m = TmModuleGetByName("DecodeSuritap")) == NULL) {
        return -1;
    }
    TmSlotSetFuncAppend(tv, m, NULL);
    if ((m = TmModuleGetByName("FlowWorker")) == NULL) {
        return -1;
    }
    TmSlotSetFuncAppend(tv, m, NULL);
    TmThreadSetCPU(tv, WORKER_CPU_SET);
    return TmThreadSpawn(tv) == TM_ECODE_OK ? 0 : -1;
}

void suritap_time_mode_live(void)
{
    TimeModeSetLive();
}

void suritap_engine_mode_ips(void)
{
    EngineModeSetIPS();
}

int suritap_should_stop(void)
{
    return suricata_ctl_flags != 0;
}

void suritap_thread_running(ThreadVars *tv)
{
    TmThreadsSetFlag(tv, THV_RUNNING);
}

void *suritap_slot_next(void *slot)
{
    return ((TmSlot *)slot)->slot_next;
}

void suritap_capture_timeout(ThreadVars *tv)
{
    TmThreadsCaptureHandleTimeout(tv, NULL);
}

/* --- packets --- */

Packet *suritap_packet_get(void)
{
    PacketPoolWait();
    return PacketGetFromQueueOrAlloc();
}

/* Prepares a pool packet that points (zero copy) at a synthesized raw IP
 * packet owned by the plugin. */
void suritap_packet_setup(Packet *p, const uint8_t *data, uint32_t len, LiveDevice *dev,
        void (*release)(Packet *), uint32_t tenant, uint16_t vlan0, uint16_t vlan1)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    SCPacketSetSource(p, PKT_SRC_WIRE);
    SCPacketSetTime(p, SCTIME_FROM_TIMEVAL(&now));
    SCPacketSetDatalink(p, LINKTYPE_RAW);
    SCPacketSetLiveDevice(p, dev);
    SCPacketSetReleasePacket(p, release);
    /* TCP checksums are not computed by the synthesizer. */
    p->flags |= PKT_IGNORE_CHECKSUM;
    p->tenant_id = tenant;
    /* Per-connection discriminator: part of the flow key (vlan.use-for-tracking). */
    if (vlan0 != 0) {
        p->vlan_id[0] = vlan0;
        p->vlan_id[1] = vlan1;
        p->vlan_idx = vlan1 != 0 ? 2 : 1;
    }
    PacketSetData(p, data, len);
}

int suritap_process(ThreadVars *tv, void *slot_next, Packet *p, LiveDevice *dev)
{
    if (dev != NULL) {
        LiveDevicePktsIncr(dev);
    }
    return TmThreadsSlotProcessPkt(tv, slot_next, p) == TM_ECODE_OK ? 0 : -1;
}

void suritap_packet_return(ThreadVars *tv, Packet *p)
{
    TmqhOutputPacketpool(tv, p);
}

const uint8_t *suritap_packet_data(const Packet *p)
{
    return GET_PKT_DATA(p);
}

static uint8_t SuritapReason(uint8_t r)
{
    switch (r) {
        case PKT_DROP_REASON_RULES:
        case PKT_DROP_REASON_RULES_THRESHOLD:
        case PKT_DROP_REASON_FW_RULES:
        case PKT_DROP_REASON_FW_DEFAULT_PACKET_POLICY:
        case PKT_DROP_REASON_FW_DEFAULT_APP_POLICY:
        case PKT_DROP_REASON_FW_STREAM_PRE_HOOK:
        case PKT_DROP_REASON_FW_FLOW_PRE_HOOK:
            return SURITAP_REASON_RULE;
        case PKT_DROP_REASON_FLOW_DROP:
        case PKT_DROP_REASON_FW_FLOW_DROP:
            return SURITAP_REASON_FLOW;
        default:
            return SURITAP_REASON_POLICY;
    }
}

static void SuritapAddAlert(SuritapOutcome *o, const PacketAlert *pa)
{
    if (pa->s == NULL || o->n_alerts >= 8) {
        return;
    }
    SuritapAlert *a = &o->alerts[o->n_alerts++];
    a->sid = pa->s->id;
    a->gid = pa->s->gid;
    a->rev = pa->s->rev;
    a->action = pa->action;
}

/* Called from the packet release callback, before the packet is recycled. */
void suritap_packet_outcome(const Packet *p, SuritapOutcome *o)
{
    o->action = p->action;
    o->drop_reason = p->drop_reason;
    o->reason = (p->action & ACTION_DROP_REJECT) ? SuritapReason(p->drop_reason) : 0;
    o->alert_total = p->alerts.cnt;
    o->n_alerts = 0;
    for (uint16_t i = 0; i < p->alerts.cnt; i++) {
        SuritapAddAlert(o, &p->alerts.alerts[i]);
    }
    if (o->n_alerts == 0 && (p->action & ACTION_DROP_REJECT) && p->alerts.drop.s != NULL) {
        SuritapAddAlert(o, &p->alerts.drop);
        o->alert_total = 1;
    }
}

/* Bypass decisions (stream depth, bypass keyword) put the flow in local
 * bypass; capture-level offload callbacks only exist in builds with
 * CAPTURE_OFFLOAD, so the state is checked from a flow update callback. */
int suritap_flow_bypassed(const Flow *f)
{
    return f->flow_state == FLOW_STATE_LOCAL_BYPASSED
#ifdef CAPTURE_OFFLOAD
           || f->flow_state == FLOW_STATE_CAPTURE_BYPASSED
#endif
            ;
}

void suritap_packet_release(Packet *p)
{
    PacketFreeOrRelease(p);
}
