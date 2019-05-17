/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2008, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*!
 * \file
 *
 * \brief Supports RTP and RTCP with Symmetric RTP support for NAT traversal.
 *
 * \author Mark Spencer <markster@digium.com>
 *
 * \note RTP is defined in RFC 3550.
 *
 * \ingroup rtp_engines
 */

/*** MODULEINFO
	<use type="external">openssl</use>
	<use type="external">pjproject</use>
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

#include <sys/time.h>
#include <signal.h>
#include <fcntl.h>

#ifdef HAVE_OPENSSL
#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>
#if !defined(OPENSSL_NO_SRTP) && (OPENSSL_VERSION_NUMBER >= 0x10001000L)
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#if !defined(OPENSSL_NO_ECDH) && (OPENSSL_VERSION_NUMBER >= 0x10000000L)
#include <openssl/bn.h>
#endif
#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif
#endif
#endif

#ifdef HAVE_PJPROJECT
#include <pjlib.h>
#include <pjlib-util.h>
#include <pjnath.h>
#include <ifaddrs.h>
#endif

#include "asterisk/options.h"
#include "asterisk/stun.h"
#include "asterisk/pbx.h"
#include "asterisk/frame.h"
#include "asterisk/format_cache.h"
#include "asterisk/channel.h"
#include "asterisk/acl.h"
#include "asterisk/config.h"
#include "asterisk/lock.h"
#include "asterisk/utils.h"
#include "asterisk/cli.h"
#include "asterisk/manager.h"
#include "asterisk/unaligned.h"
#include "asterisk/module.h"
#include "asterisk/rtp_engine.h"
#include "asterisk/smoother.h"
#include "asterisk/uuid.h"
#include "asterisk/test.h"
#include "asterisk/data_buffer.h"
#ifdef HAVE_PJPROJECT
#include "asterisk/res_pjproject.h"
#endif

#define MAX_TIMESTAMP_SKEW	640

#define RTP_SEQ_MOD     (1<<16)	/*!< A sequence number can't be more than 16 bits */
#define RTCP_DEFAULT_INTERVALMS   5000	/*!< Default milli-seconds between RTCP reports we send */
#define RTCP_MIN_INTERVALMS       500	/*!< Min milli-seconds between RTCP reports we send */
#define RTCP_MAX_INTERVALMS       60000	/*!< Max milli-seconds between RTCP reports we send */

#define DEFAULT_RTP_START 5000 /*!< Default port number to start allocating RTP ports from */
#define DEFAULT_RTP_END 31000  /*!< Default maximum port number to end allocating RTP ports at */

#define MINIMUM_RTP_PORT 1024 /*!< Minimum port number to accept */
#define MAXIMUM_RTP_PORT 65535 /*!< Maximum port number to accept */

#define DEFAULT_TURN_PORT 3478

#define TURN_STATE_WAIT_TIME 2000

#define DEFAULT_RTP_SEND_BUFFER_SIZE	250
#define DEFAULT_RTP_RECV_BUFFER_SIZE	20

/*! Full INTRA-frame Request / Fast Update Request (From RFC2032) */
#define RTCP_PT_FUR     192
/*! Sender Report (From RFC3550) */
#define RTCP_PT_SR      AST_RTP_RTCP_SR
/*! Receiver Report (From RFC3550) */
#define RTCP_PT_RR      AST_RTP_RTCP_RR
/*! Source Description (From RFC3550) */
#define RTCP_PT_SDES    202
/*! Goodbye (To remove SSRC's from tables) (From RFC3550) */
#define RTCP_PT_BYE     203
/*! Application defined (From RFC3550) */
#define RTCP_PT_APP     204
/* VP8: RTCP Feedback */
/*! Payload Specific Feed Back (From RFC4585 also RFC5104) */
#define RTCP_PT_PSFB    AST_RTP_RTCP_PSFB

#define RTP_MTU		1200
#define DTMF_SAMPLE_RATE_MS    8 /*!< DTMF samples per millisecond */

#define DEFAULT_DTMF_TIMEOUT (150 * (8000 / 1000))	/*!< samples */

#define ZFONE_PROFILE_ID 0x505a

#define DEFAULT_LEARNING_MIN_SEQUENTIAL 4
/*!
 * \brief Calculate the min learning duration in ms.
 *
 * \details
 * The min supported packet size represents 10 ms and we need to account
 * for some jitter and fast clocks while learning.  Some messed up devices
 * have very bad jitter for a small packet sample size.  Jitter can also
 * be introduced by the network itself.
 *
 * So we'll allow packets to come in every 9ms on average for fast clocking
 * with the last one coming in 5ms early for jitter.
 */
#define CALC_LEARNING_MIN_DURATION(count) (((count) - 1) * 9 - 5)
#define DEFAULT_LEARNING_MIN_DURATION CALC_LEARNING_MIN_DURATION(DEFAULT_LEARNING_MIN_SEQUENTIAL)

#define SRTP_MASTER_KEY_LEN 16
#define SRTP_MASTER_SALT_LEN 14
#define SRTP_MASTER_LEN (SRTP_MASTER_KEY_LEN + SRTP_MASTER_SALT_LEN)

#define RTP_DTLS_ESTABLISHED -37

enum strict_rtp_state {
	STRICT_RTP_OPEN = 0, /*! No RTP packets should be dropped, all sources accepted */
	STRICT_RTP_LEARN,    /*! Accept next packet as source */
	STRICT_RTP_CLOSED,   /*! Drop all RTP packets not coming from source that was learned */
};

enum strict_rtp_mode {
	STRICT_RTP_NO = 0,	/*! Don't adhere to any strict RTP rules */
	STRICT_RTP_YES,		/*! Strict RTP that restricts packets based on time and sequence number */
	STRICT_RTP_SEQNO,	/*! Strict RTP that restricts packets based on sequence number */
};

/*!
 * \brief Strict RTP learning timeout time in milliseconds
 *
 * \note Set to 5 seconds to allow reinvite chains for direct media
 * to settle before media actually starts to arrive.  There may be a
 * reinvite collision involved on the other leg.
 */
#define STRICT_RTP_LEARN_TIMEOUT	5000

#define DEFAULT_STRICT_RTP STRICT_RTP_YES	/*!< Enabled by default */
#define DEFAULT_ICESUPPORT 1

extern struct ast_srtp_res *res_srtp;
extern struct ast_srtp_policy_res *res_srtp_policy;

static int dtmftimeout = DEFAULT_DTMF_TIMEOUT;

static int rtpstart = DEFAULT_RTP_START;			/*!< First port for RTP sessions (set in rtp.conf) */
static int rtpend = DEFAULT_RTP_END;			/*!< Last port for RTP sessions (set in rtp.conf) */
static int rtpdebug;			/*!< Are we debugging? */
static int rtcpdebug;			/*!< Are we debugging RTCP? */
static int rtcpstats;			/*!< Are we debugging RTCP? */
static int rtcpinterval = RTCP_DEFAULT_INTERVALMS; /*!< Time between rtcp reports in millisecs */
static struct ast_sockaddr rtpdebugaddr;	/*!< Debug packets to/from this host */
static struct ast_sockaddr rtcpdebugaddr;	/*!< Debug RTCP packets to/from this host */
static int rtpdebugport;		/*!< Debug only RTP packets from IP or IP+Port if port is > 0 */
static int rtcpdebugport;		/*!< Debug only RTCP packets from IP or IP+Port if port is > 0 */
#ifdef SO_NO_CHECK
static int nochecksums;
#endif
static int strictrtp = DEFAULT_STRICT_RTP; /*!< Only accept RTP frames from a defined source. If we receive an indication of a changing source, enter learning mode. */
static int learning_min_sequential = DEFAULT_LEARNING_MIN_SEQUENTIAL; /*!< Number of sequential RTP frames needed from a single source during learning mode to accept new source. */
static int learning_min_duration = DEFAULT_LEARNING_MIN_DURATION; /*!< Lowest acceptable timeout between the first and the last sequential RTP frame. */
#ifdef HAVE_PJPROJECT
static int icesupport = DEFAULT_ICESUPPORT;
static struct sockaddr_in stunaddr;
static pj_str_t turnaddr;
static int turnport = DEFAULT_TURN_PORT;
static pj_str_t turnusername;
static pj_str_t turnpassword;

static struct ast_ha *ice_blacklist = NULL;    /*!< Blacklisted ICE networks */
static ast_rwlock_t ice_blacklist_lock = AST_RWLOCK_INIT_VALUE;

/*! Blacklisted networks for STUN requests */
static struct ast_ha *stun_blacklist = NULL;
static ast_rwlock_t stun_blacklist_lock = AST_RWLOCK_INIT_VALUE;


/*! \brief Pool factory used by pjlib to allocate memory. */
static pj_caching_pool cachingpool;

/*! \brief Global memory pool for configuration and timers */
static pj_pool_t *pool;

/*! \brief Global timer heap */
static pj_timer_heap_t *timer_heap;

/*! \brief Thread executing the timer heap */
static pj_thread_t *timer_thread;

/*! \brief Used to tell the timer thread to terminate */
static int timer_terminate;

/*! \brief Structure which contains ioqueue thread information */
struct ast_rtp_ioqueue_thread {
	/*! \brief Pool used by the thread */
	pj_pool_t *pool;
	/*! \brief The thread handling the queue and timer heap */
	pj_thread_t *thread;
	/*! \brief Ioqueue which polls on sockets */
	pj_ioqueue_t *ioqueue;
	/*! \brief Timer heap for scheduled items */
	pj_timer_heap_t *timerheap;
	/*! \brief Termination request */
	int terminate;
	/*! \brief Current number of descriptors being waited on */
	unsigned int count;
	/*! \brief Linked list information */
	AST_LIST_ENTRY(ast_rtp_ioqueue_thread) next;
};

/*! \brief List of ioqueue threads */
static AST_LIST_HEAD_STATIC(ioqueues, ast_rtp_ioqueue_thread);

/*! \brief Structure which contains ICE host candidate mapping information */
struct ast_ice_host_candidate {
	pj_sockaddr local;
	pj_sockaddr advertised;
	unsigned int include_local;
	AST_RWLIST_ENTRY(ast_ice_host_candidate) next;
};

/*! \brief List of ICE host candidate mappings */
static AST_RWLIST_HEAD_STATIC(host_candidates, ast_ice_host_candidate);

#endif

#define FLAG_3389_WARNING               (1 << 0)
#define FLAG_NAT_ACTIVE                 (3 << 1)
#define FLAG_NAT_INACTIVE               (0 << 1)
#define FLAG_NAT_INACTIVE_NOWARN        (1 << 1)
#define FLAG_NEED_MARKER_BIT            (1 << 3)
#define FLAG_DTMF_COMPENSATE            (1 << 4)
#define FLAG_REQ_LOCAL_BRIDGE_BIT       (1 << 5)

#define TRANSPORT_SOCKET_RTP 0
#define TRANSPORT_SOCKET_RTCP 1
#define TRANSPORT_TURN_RTP 2
#define TRANSPORT_TURN_RTCP 3

/*! \brief RTP learning mode tracking information */
struct rtp_learning_info {
	struct ast_sockaddr proposed_address;	/*!< Proposed remote address for strict RTP */
	struct timeval start;	/*!< The time learning mode was started */
	struct timeval received; /*!< The time of the first received packet */
	int max_seq;	/*!< The highest sequence number received */
	int packets;	/*!< The number of remaining packets before the source is accepted */
	/*! Type of media stream carried by the RTP instance */
	enum ast_media_type stream_type;
};

#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
struct dtls_details {
	SSL *ssl;         /*!< SSL session */
	BIO *read_bio;    /*!< Memory buffer for reading */
	BIO *write_bio;   /*!< Memory buffer for writing */
	enum ast_rtp_dtls_setup dtls_setup; /*!< Current setup state */
	enum ast_rtp_dtls_connection connection; /*!< Whether this is a new or existing connection */
	int timeout_timer; /*!< Scheduler id for timeout timer */
};
#endif

#ifdef HAVE_PJPROJECT
/*! An ao2 wrapper protecting the PJPROJECT ice structure with ref counting. */
struct ice_wrap {
	pj_ice_sess *real_ice;           /*!< ICE session */
};
#endif

/*! \brief Structure used for mapping an incoming SSRC to an RTP instance */
struct rtp_ssrc_mapping {
	/*! \brief The received SSRC */
	unsigned int ssrc;
	/*! True if the SSRC is available.  Otherwise, this is a placeholder mapping until the SSRC is set. */
	unsigned int ssrc_valid;
	/*! \brief The RTP instance this SSRC belongs to*/
	struct ast_rtp_instance *instance;
};

/*! \brief RTP session description */
struct ast_rtp {
	int s;
	/*! \note The f.subclass.format holds a ref. */
	struct ast_frame f;
	unsigned char rawdata[8192 + AST_FRIENDLY_OFFSET];
	unsigned int ssrc;		/*!< Synchronization source, RFC 3550, page 10. */
	char cname[AST_UUID_STR_LEN]; /*!< Our local CNAME */
	unsigned int themssrc;		/*!< Their SSRC */
	unsigned int themssrc_valid;	/*!< True if their SSRC is available. */
	unsigned int lastts;
	unsigned int lastividtimestamp;
	unsigned int lastovidtimestamp;
	unsigned int lastitexttimestamp;
	unsigned int lastotexttimestamp;
	int lastrxseqno;                /*!< Last received sequence number, from the network */
	int expectedrxseqno;		/*!< Next expected sequence number, from the network */
	AST_VECTOR(, int) missing_seqno; /*!< A vector of sequence numbers we never received */
	int expectedseqno;		/*!< Next expected sequence number, from the core */
	unsigned short seedrxseqno;     /*!< What sequence number did they start with?*/
	unsigned int seedrxts;          /*!< What RTP timestamp did they start with? */
	unsigned int rxcount;           /*!< How many packets have we received? */
	unsigned int rxoctetcount;      /*!< How many octets have we received? should be rxcount *160*/
	unsigned int txcount;           /*!< How many packets have we sent? */
	unsigned int txoctetcount;      /*!< How many octets have we sent? (txcount*160)*/
	unsigned int cycles;            /*!< Shifted count of sequence number cycles */
	double rxjitter;                /*!< Interarrival jitter at the moment in seconds */
	double rxtransit;               /*!< Relative transit time for previous packet */
	struct ast_format *lasttxformat;
	struct ast_format *lastrxformat;

	/* DTMF Reception Variables */
	char resp;                        /*!< The current digit being processed */
	unsigned int last_seqno;          /*!< The last known sequence number for any DTMF packet */
	unsigned int last_end_timestamp;  /*!< The last known timestamp received from an END packet */
	unsigned int dtmf_duration;       /*!< Total duration in samples since the digit start event */
	unsigned int dtmf_timeout;        /*!< When this timestamp is reached we consider END frame lost and forcibly abort digit */
	unsigned int dtmfsamples;
	enum ast_rtp_dtmf_mode dtmfmode;  /*!< The current DTMF mode of the RTP stream */
	/* DTMF Transmission Variables */
	unsigned int lastdigitts;
	char sending_digit;	/*!< boolean - are we sending digits */
	char send_digit;	/*!< digit we are sending */
	int send_payload;
	int send_duration;
	unsigned int flags;
	struct timeval rxcore;
	struct timeval txcore;
	double drxcore;                 /*!< The double representation of the first received packet */
	struct timeval dtmfmute;
	struct ast_smoother *smoother;
	unsigned short seqno;		/*!< Sequence number, RFC 3550, page 13. */
	struct ast_sched_context *sched;
	struct ast_rtcp *rtcp;
	unsigned int asymmetric_codec;  /*!< Indicate if asymmetric send/receive codecs are allowed */

	struct ast_rtp_instance *bundled; /*!< The RTP instance we are bundled to */
	int stream_num; /*!< Stream num for this RTP instance */
	AST_VECTOR(, struct rtp_ssrc_mapping) ssrc_mapping; /*!< Mappings of SSRC to RTP instances */
	struct ast_sockaddr bind_address; /*!< Requested bind address for the sockets */

	enum strict_rtp_state strict_rtp_state; /*!< Current state that strict RTP protection is in */
	struct ast_sockaddr strict_rtp_address;  /*!< Remote address information for strict RTP purposes */

	/*
	 * Learning mode values based on pjmedia's probation mode.  Many of these values are redundant to the above,
	 * but these are in place to keep learning mode sequence values sealed from their normal counterparts.
	 */
	struct rtp_learning_info rtp_source_learn;	/* Learning mode track for the expected RTP source */

	struct rtp_red *red;

	struct ast_data_buffer *send_buffer;		/*!< Buffer for storing sent packets for retransmission */
	struct ast_data_buffer *recv_buffer;		/*!< Buffer for storing received packets for retransmission */

#ifdef HAVE_PJPROJECT
	ast_cond_t cond;            /*!< ICE/TURN condition for signaling */

	struct ice_wrap *ice;       /*!< ao2 wrapped ICE session */
	enum ast_rtp_ice_role role; /*!< Our role in ICE negotiation */
	pj_turn_sock *turn_rtp;     /*!< RTP TURN relay */
	pj_turn_sock *turn_rtcp;    /*!< RTCP TURN relay */
	pj_turn_state_t turn_state; /*!< Current state of the TURN relay session */
	unsigned int passthrough:1; /*!< Bit to indicate that the received packet should be passed through */
	unsigned int rtp_passthrough:1; /*!< Bit to indicate that TURN RTP should be passed through */
	unsigned int rtcp_passthrough:1; /*!< Bit to indicate that TURN RTCP should be passed through */
	unsigned int ice_port;      /*!< Port that ICE was started with if it was previously started */
	struct ast_sockaddr rtp_loop; /*!< Loopback address for forwarding RTP from TURN */
	struct ast_sockaddr rtcp_loop; /*!< Loopback address for forwarding RTCP from TURN */

	struct ast_rtp_ioqueue_thread *ioqueue; /*!< The ioqueue thread handling us */

	char remote_ufrag[256];  /*!< The remote ICE username */
	char remote_passwd[256]; /*!< The remote ICE password */

	char local_ufrag[256];  /*!< The local ICE username */
	char local_passwd[256]; /*!< The local ICE password */

	struct ao2_container *ice_local_candidates;           /*!< The local ICE candidates */
	struct ao2_container *ice_active_remote_candidates;   /*!< The remote ICE candidates */
	struct ao2_container *ice_proposed_remote_candidates; /*!< Incoming remote ICE candidates for new session */
	struct ast_sockaddr ice_original_rtp_addr;            /*!< rtp address that ICE started on first session */
	unsigned int ice_num_components; /*!< The number of ICE components */
#endif

#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
	SSL_CTX *ssl_ctx; /*!< SSL context */
	enum ast_rtp_dtls_verify dtls_verify; /*!< What to verify */
	enum ast_srtp_suite suite;   /*!< SRTP crypto suite */
	enum ast_rtp_dtls_hash local_hash; /*!< Local hash used for the fingerprint */
	char local_fingerprint[160]; /*!< Fingerprint of our certificate */
	enum ast_rtp_dtls_hash remote_hash; /*!< Remote hash used for the fingerprint */
	unsigned char remote_fingerprint[EVP_MAX_MD_SIZE]; /*!< Fingerprint of the peer certificate */
	unsigned int rekey; /*!< Interval at which to renegotiate and rekey */
	int rekeyid; /*!< Scheduled item id for rekeying */
	struct dtls_details dtls; /*!< DTLS state information */
#endif
};

/*!
 * \brief Structure defining an RTCP session.
 *
 * The concept "RTCP session" is not defined in RFC 3550, but since
 * this structure is analogous to ast_rtp, which tracks a RTP session,
 * it is logical to think of this as a RTCP session.
 *
 * RTCP packet is defined on page 9 of RFC 3550.
 *
 */
struct ast_rtcp {
	int rtcp_info;
	int s;				/*!< Socket */
	struct ast_sockaddr us;		/*!< Socket representation of the local endpoint. */
	struct ast_sockaddr them;	/*!< Socket representation of the remote endpoint. */
	unsigned int soc;		/*!< What they told us */
	unsigned int spc;		/*!< What they told us */
	unsigned int themrxlsr;		/*!< The middle 32 bits of the NTP timestamp in the last received SR*/
	struct timeval rxlsr;		/*!< Time when we got their last SR */
	struct timeval txlsr;		/*!< Time when we sent or last SR*/
	unsigned int expected_prior;	/*!< no. packets in previous interval */
	unsigned int received_prior;	/*!< no. packets received in previous interval */
	int schedid;			/*!< Schedid returned from ast_sched_add() to schedule RTCP-transmissions*/
	unsigned int rr_count;		/*!< number of RRs we've sent, not including report blocks in SR's */
	unsigned int sr_count;		/*!< number of SRs we've sent */
	unsigned int lastsrtxcount;     /*!< Transmit packet count when last SR sent */
	double accumulated_transit;	/*!< accumulated a-dlsr-lsr */
	double rtt;			/*!< Last reported rtt */
	unsigned int reported_jitter;	/*!< The contents of their last jitter entry in the RR */
	unsigned int reported_lost;	/*!< Reported lost packets in their RR */

	double reported_maxjitter;
	double reported_minjitter;
	double reported_normdev_jitter;
	double reported_stdev_jitter;
	unsigned int reported_jitter_count;

	double reported_maxlost;
	double reported_minlost;
	double reported_normdev_lost;
	double reported_stdev_lost;

	double rxlost;
	double maxrxlost;
	double minrxlost;
	double normdev_rxlost;
	double stdev_rxlost;
	unsigned int rxlost_count;

	double maxrxjitter;
	double minrxjitter;
	double normdev_rxjitter;
	double stdev_rxjitter;
	unsigned int rxjitter_count;
	double maxrtt;
	double minrtt;
	double normdevrtt;
	double stdevrtt;
	unsigned int rtt_count;

	/* VP8: sequence number for the RTCP FIR FCI */
	int firseq;

#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
	struct dtls_details dtls; /*!< DTLS state information */
#endif

	/* Cached local address string allows us to generate
	 * RTCP stasis messages without having to look up our
	 * own address every time
	 */
	char *local_addr_str;
	enum ast_rtp_instance_rtcp type;
	/* Buffer for frames created during RTCP interpretation */
	unsigned char frame_buf[512 + AST_FRIENDLY_OFFSET];
};

struct rtp_red {
	struct ast_frame t140;  /*!< Primary data  */
	struct ast_frame t140red;   /*!< Redundant t140*/
	unsigned char pt[AST_RED_MAX_GENERATION];  /*!< Payload types for redundancy data */
	unsigned char ts[AST_RED_MAX_GENERATION]; /*!< Time stamps */
	unsigned char len[AST_RED_MAX_GENERATION]; /*!< length of each generation */
	int num_gen; /*!< Number of generations */
	int schedid; /*!< Timer id */
	int ti; /*!< How long to buffer data before send */
	unsigned char t140red_data[64000];
	unsigned char buf_data[64000]; /*!< buffered primary data */
	int hdrlen;
	long int prev_ts;
};

/*! \brief Structure for storing RTP packets for retransmission */
struct ast_rtp_rtcp_nack_payload {
	size_t size;		/*!< The size of the payload */
	unsigned char buf[0];	/*!< The payload data */
};

AST_LIST_HEAD_NOLOCK(frame_list, ast_frame);

/* Forward Declarations */
static int ast_rtp_new(struct ast_rtp_instance *instance, struct ast_sched_context *sched, struct ast_sockaddr *addr, void *data);
static int ast_rtp_destroy(struct ast_rtp_instance *instance);
static int ast_rtp_dtmf_begin(struct ast_rtp_instance *instance, char digit);
static int ast_rtp_dtmf_end(struct ast_rtp_instance *instance, char digit);
static int ast_rtp_dtmf_end_with_duration(struct ast_rtp_instance *instance, char digit, unsigned int duration);
static int ast_rtp_dtmf_mode_set(struct ast_rtp_instance *instance, enum ast_rtp_dtmf_mode dtmf_mode);
static enum ast_rtp_dtmf_mode ast_rtp_dtmf_mode_get(struct ast_rtp_instance *instance);
static void ast_rtp_update_source(struct ast_rtp_instance *instance);
static void ast_rtp_change_source(struct ast_rtp_instance *instance);
static int ast_rtp_write(struct ast_rtp_instance *instance, struct ast_frame *frame);
static struct ast_frame *ast_rtp_read(struct ast_rtp_instance *instance, int rtcp);
static void ast_rtp_prop_set(struct ast_rtp_instance *instance, enum ast_rtp_property property, int value);
static int ast_rtp_fd(struct ast_rtp_instance *instance, int rtcp);
static void ast_rtp_remote_address_set(struct ast_rtp_instance *instance, struct ast_sockaddr *addr);
static int rtp_red_init(struct ast_rtp_instance *instance, int buffer_time, int *payloads, int generations);
static int rtp_red_buffer(struct ast_rtp_instance *instance, struct ast_frame *frame);
static int ast_rtp_local_bridge(struct ast_rtp_instance *instance0, struct ast_rtp_instance *instance1);
static int ast_rtp_get_stat(struct ast_rtp_instance *instance, struct ast_rtp_instance_stats *stats, enum ast_rtp_instance_stat stat);
static int ast_rtp_dtmf_compatible(struct ast_channel *chan0, struct ast_rtp_instance *instance0, struct ast_channel *chan1, struct ast_rtp_instance *instance1);
static void ast_rtp_stun_request(struct ast_rtp_instance *instance, struct ast_sockaddr *suggestion, const char *username);
static void ast_rtp_stop(struct ast_rtp_instance *instance);
static int ast_rtp_qos_set(struct ast_rtp_instance *instance, int tos, int cos, const char* desc);
static int ast_rtp_sendcng(struct ast_rtp_instance *instance, int level);
static unsigned int ast_rtp_get_ssrc(struct ast_rtp_instance *instance);
static const char *ast_rtp_get_cname(struct ast_rtp_instance *instance);
static void ast_rtp_set_remote_ssrc(struct ast_rtp_instance *instance, unsigned int ssrc);
static void ast_rtp_set_stream_num(struct ast_rtp_instance *instance, int stream_num);
static int ast_rtp_extension_enable(struct ast_rtp_instance *instance, enum ast_rtp_extension extension);
static int ast_rtp_bundle(struct ast_rtp_instance *child, struct ast_rtp_instance *parent);

#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
static int ast_rtp_activate(struct ast_rtp_instance *instance);
static void dtls_srtp_check_pending(struct ast_rtp_instance *instance, struct ast_rtp *rtp, int rtcp);
static void dtls_srtp_start_timeout_timer(struct ast_rtp_instance *instance, struct ast_rtp *rtp, int rtcp);
static void dtls_srtp_stop_timeout_timer(struct ast_rtp_instance *instance, struct ast_rtp *rtp, int rtcp);
#endif

static int __rtp_sendto(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa, int rtcp, int *via_ice, int use_srtp);

#ifdef HAVE_PJPROJECT
/*! \brief Helper function which clears the ICE host candidate mapping */
static void host_candidate_overrides_clear(void)
{
	struct ast_ice_host_candidate *candidate;

	AST_RWLIST_WRLOCK(&host_candidates);
	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&host_candidates, candidate, next) {
		AST_RWLIST_REMOVE_CURRENT(next);
		ast_free(candidate);
	}
	AST_RWLIST_TRAVERSE_SAFE_END;
	AST_RWLIST_UNLOCK(&host_candidates);
}

/*! \brief Applies the ICE host candidate mapping */
static unsigned int host_candidate_overrides_apply(unsigned int count, unsigned int max_count, pj_sockaddr addrs[])
{
	int pos;
	struct ast_ice_host_candidate *candidate;
	unsigned int added = 0;

	AST_RWLIST_RDLOCK(&host_candidates);
	for (pos = 0; pos < count; pos++) {
		AST_LIST_TRAVERSE(&host_candidates, candidate, next) {
			if (!pj_sockaddr_cmp(&candidate->local, &addrs[pos])) {
				pj_sockaddr_copy_addr(&addrs[pos], &candidate->advertised);
				if (candidate->include_local && (count + (++added)) <= max_count) {
					pj_sockaddr_cp(&addrs[count + (added - 1)], &candidate->local);
				}
				break;
			}
		}
	}
	AST_RWLIST_UNLOCK(&host_candidates);
	return added;
}

/*! \brief Helper function which updates an ast_sockaddr with the candidate used for the component */
static void update_address_with_ice_candidate(pj_ice_sess *ice, enum ast_rtp_ice_component_type component,
	struct ast_sockaddr *cand_address)
{
	char address[PJ_INET6_ADDRSTRLEN];

	if (component < 1 || !ice->comp[component - 1].valid_check) {
		return;
	}

	ast_sockaddr_parse(cand_address,
		pj_sockaddr_print(&ice->comp[component - 1].valid_check->rcand->addr, address,
			sizeof(address), 0), 0);
	ast_sockaddr_set_port(cand_address,
		pj_sockaddr_get_port(&ice->comp[component - 1].valid_check->rcand->addr));
}

/*! \brief Destructor for locally created ICE candidates */
static void ast_rtp_ice_candidate_destroy(void *obj)
{
	struct ast_rtp_engine_ice_candidate *candidate = obj;

	if (candidate->foundation) {
		ast_free(candidate->foundation);
	}

	if (candidate->transport) {
		ast_free(candidate->transport);
	}
}

/*! \pre instance is locked */
static void ast_rtp_ice_set_authentication(struct ast_rtp_instance *instance, const char *ufrag, const char *password)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (!ast_strlen_zero(ufrag)) {
		ast_copy_string(rtp->remote_ufrag, ufrag, sizeof(rtp->remote_ufrag));
	}

	if (!ast_strlen_zero(password)) {
		ast_copy_string(rtp->remote_passwd, password, sizeof(rtp->remote_passwd));
	}
}

static int ice_candidate_cmp(void *obj, void *arg, int flags)
{
	struct ast_rtp_engine_ice_candidate *candidate1 = obj, *candidate2 = arg;

	if (strcmp(candidate1->foundation, candidate2->foundation) ||
			candidate1->id != candidate2->id ||
			candidate1->type != candidate2->type ||
			ast_sockaddr_cmp(&candidate1->address, &candidate2->address)) {
		return 0;
	}

	return CMP_MATCH | CMP_STOP;
}

/*! \pre instance is locked */
static void ast_rtp_ice_add_remote_candidate(struct ast_rtp_instance *instance, const struct ast_rtp_engine_ice_candidate *candidate)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_rtp_engine_ice_candidate *remote_candidate;

	/* ICE sessions only support UDP candidates */
	if (strcasecmp(candidate->transport, "udp")) {
		return;
	}

	if (!rtp->ice_proposed_remote_candidates) {
		rtp->ice_proposed_remote_candidates = ao2_container_alloc_list(
			AO2_ALLOC_OPT_LOCK_MUTEX, 0, NULL, ice_candidate_cmp);
		if (!rtp->ice_proposed_remote_candidates) {
			return;
		}
	}

	/* If this is going to exceed the maximum number of ICE candidates don't even add it */
	if (ao2_container_count(rtp->ice_proposed_remote_candidates) == PJ_ICE_MAX_CAND) {
		return;
	}

	if (!(remote_candidate = ao2_alloc(sizeof(*remote_candidate), ast_rtp_ice_candidate_destroy))) {
		return;
	}

	remote_candidate->foundation = ast_strdup(candidate->foundation);
	remote_candidate->id = candidate->id;
	remote_candidate->transport = ast_strdup(candidate->transport);
	remote_candidate->priority = candidate->priority;
	ast_sockaddr_copy(&remote_candidate->address, &candidate->address);
	ast_sockaddr_copy(&remote_candidate->relay_address, &candidate->relay_address);
	remote_candidate->type = candidate->type;

	ao2_link(rtp->ice_proposed_remote_candidates, remote_candidate);
	ao2_ref(remote_candidate, -1);
}

AST_THREADSTORAGE(pj_thread_storage);

/*! \brief Function used to check if the calling thread is registered with pjlib. If it is not it will be registered. */
static void pj_thread_register_check(void)
{
	pj_thread_desc *desc;
	pj_thread_t *thread;

	if (pj_thread_is_registered() == PJ_TRUE) {
		return;
	}

	desc = ast_threadstorage_get(&pj_thread_storage, sizeof(pj_thread_desc));
	if (!desc) {
		ast_log(LOG_ERROR, "Could not get thread desc from thread-local storage. Expect awful things to occur\n");
		return;
	}
	pj_bzero(*desc, sizeof(*desc));

	if (pj_thread_register("Asterisk Thread", *desc, &thread) != PJ_SUCCESS) {
		ast_log(LOG_ERROR, "Coudln't register thread with PJLIB.\n");
	}
	return;
}

static int ice_create(struct ast_rtp_instance *instance, struct ast_sockaddr *addr,
	int port, int replace);

/*! \pre instance is locked */
static void ast_rtp_ice_stop(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ice_wrap *ice;

	ice = rtp->ice;
	rtp->ice = NULL;
	if (ice) {
		/* Release the instance lock to avoid deadlock with PJPROJECT group lock */
		ao2_unlock(instance);
		ao2_ref(ice, -1);
		ao2_lock(instance);
	}
}

/*!
 * \brief ao2 ICE wrapper object destructor.
 *
 * \param vdoomed Object being destroyed.
 *
 * \note The associated struct ast_rtp_instance object must not
 * be locked when unreffing the object.  Otherwise we could
 * deadlock trying to destroy the PJPROJECT ICE structure.
 */
static void ice_wrap_dtor(void *vdoomed)
{
	struct ice_wrap *ice = vdoomed;

	if (ice->real_ice) {
		pj_thread_register_check();

		pj_ice_sess_destroy(ice->real_ice);
	}
}

static void ast2pj_rtp_ice_role(enum ast_rtp_ice_role ast_role, enum pj_ice_sess_role *pj_role)
{
	switch (ast_role) {
	case AST_RTP_ICE_ROLE_CONTROLLED:
		*pj_role = PJ_ICE_SESS_ROLE_CONTROLLED;
		break;
	case AST_RTP_ICE_ROLE_CONTROLLING:
		*pj_role = PJ_ICE_SESS_ROLE_CONTROLLING;
		break;
	}
}

static void pj2ast_rtp_ice_role(enum pj_ice_sess_role pj_role, enum ast_rtp_ice_role *ast_role)
{
	switch (pj_role) {
	case PJ_ICE_SESS_ROLE_CONTROLLED:
		*ast_role = AST_RTP_ICE_ROLE_CONTROLLED;
		return;
	case PJ_ICE_SESS_ROLE_CONTROLLING:
		*ast_role = AST_RTP_ICE_ROLE_CONTROLLING;
		return;
	case PJ_ICE_SESS_ROLE_UNKNOWN:
		/* Don't change anything */
		return;
	default:
		/* If we aren't explicitly handling something, it's a bug */
		ast_assert(0);
		return;
	}
}

/*! \pre instance is locked */
static int ice_reset_session(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int res;

	ast_debug(3, "Resetting ICE for RTP instance '%p'\n", instance);
	if (!rtp->ice->real_ice->is_nominating && !rtp->ice->real_ice->is_complete) {
		ast_debug(3, "Nevermind. ICE isn't ready for a reset\n");
		return 0;
	}

	ast_debug(3, "Recreating ICE session %s (%d) for RTP instance '%p'\n", ast_sockaddr_stringify(&rtp->ice_original_rtp_addr), rtp->ice_port, instance);
	res = ice_create(instance, &rtp->ice_original_rtp_addr, rtp->ice_port, 1);
	if (!res) {
		/* Use the current expected role for the ICE session */
		enum pj_ice_sess_role role = PJ_ICE_SESS_ROLE_UNKNOWN;
		ast2pj_rtp_ice_role(rtp->role, &role);
		pj_ice_sess_change_role(rtp->ice->real_ice, role);
	}

	/* If we only have one component now, and we previously set up TURN for RTCP,
	 * we need to destroy that TURN socket.
	 */
	if (rtp->ice_num_components == 1 && rtp->turn_rtcp) {
		struct timeval wait = ast_tvadd(ast_tvnow(), ast_samp2tv(TURN_STATE_WAIT_TIME, 1000));
		struct timespec ts = { .tv_sec = wait.tv_sec, .tv_nsec = wait.tv_usec * 1000, };

		rtp->turn_state = PJ_TURN_STATE_NULL;

		/* Release the instance lock to avoid deadlock with PJPROJECT group lock */
		ao2_unlock(instance);
		pj_turn_sock_destroy(rtp->turn_rtcp);
		ao2_lock(instance);
		while (rtp->turn_state != PJ_TURN_STATE_DESTROYING) {
			ast_cond_timedwait(&rtp->cond, ao2_object_get_lockaddr(instance), &ts);
		}
	}

	return res;
}

static int ice_candidates_compare(struct ao2_container *left, struct ao2_container *right)
{
	struct ao2_iterator i;
	struct ast_rtp_engine_ice_candidate *right_candidate;

	if (ao2_container_count(left) != ao2_container_count(right)) {
		return -1;
	}

	i = ao2_iterator_init(right, 0);
	while ((right_candidate = ao2_iterator_next(&i))) {
		struct ast_rtp_engine_ice_candidate *left_candidate = ao2_find(left, right_candidate, OBJ_POINTER);

		if (!left_candidate) {
			ao2_ref(right_candidate, -1);
			ao2_iterator_destroy(&i);
			return -1;
		}

		ao2_ref(left_candidate, -1);
		ao2_ref(right_candidate, -1);
	}
	ao2_iterator_destroy(&i);

	return 0;
}

/*! \pre instance is locked */
static void ast_rtp_ice_start(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	pj_str_t ufrag = pj_str(rtp->remote_ufrag), passwd = pj_str(rtp->remote_passwd);
	pj_ice_sess_cand candidates[PJ_ICE_MAX_CAND];
	struct ao2_iterator i;
	struct ast_rtp_engine_ice_candidate *candidate;
	int cand_cnt = 0, has_rtp = 0, has_rtcp = 0;

	if (!rtp->ice || !rtp->ice_proposed_remote_candidates) {
		return;
	}

	/* Check for equivalence in the lists */
	if (rtp->ice_active_remote_candidates &&
			!ice_candidates_compare(rtp->ice_proposed_remote_candidates, rtp->ice_active_remote_candidates)) {
		ast_debug(3, "Proposed == active candidates for RTP instance '%p'\n", instance);
		ao2_cleanup(rtp->ice_proposed_remote_candidates);
		rtp->ice_proposed_remote_candidates = NULL;
		/* If this ICE session is being preserved then go back to the role it currently is */
		pj2ast_rtp_ice_role(rtp->ice->real_ice->role, &rtp->role);
		return;
	}

	/* Out with the old, in with the new */
	ao2_cleanup(rtp->ice_active_remote_candidates);
	rtp->ice_active_remote_candidates = rtp->ice_proposed_remote_candidates;
	rtp->ice_proposed_remote_candidates = NULL;

	/* Reset the ICE session. Is this going to work? */
	if (ice_reset_session(instance)) {
		ast_log(LOG_NOTICE, "Failed to create replacement ICE session\n");
		return;
	}

	pj_thread_register_check();

	i = ao2_iterator_init(rtp->ice_active_remote_candidates, 0);

	while ((candidate = ao2_iterator_next(&i)) && (cand_cnt < PJ_ICE_MAX_CAND)) {
		pj_str_t address;

		/* there needs to be at least one rtp and rtcp candidate in the list */
		has_rtp |= candidate->id == AST_RTP_ICE_COMPONENT_RTP;
		has_rtcp |= candidate->id == AST_RTP_ICE_COMPONENT_RTCP;

		pj_strdup2(rtp->ice->real_ice->pool, &candidates[cand_cnt].foundation,
			candidate->foundation);
		candidates[cand_cnt].comp_id = candidate->id;
		candidates[cand_cnt].prio = candidate->priority;

		pj_sockaddr_parse(pj_AF_UNSPEC(), 0, pj_cstr(&address, ast_sockaddr_stringify(&candidate->address)), &candidates[cand_cnt].addr);

		if (!ast_sockaddr_isnull(&candidate->relay_address)) {
			pj_sockaddr_parse(pj_AF_UNSPEC(), 0, pj_cstr(&address, ast_sockaddr_stringify(&candidate->relay_address)), &candidates[cand_cnt].rel_addr);
		}

		if (candidate->type == AST_RTP_ICE_CANDIDATE_TYPE_HOST) {
			candidates[cand_cnt].type = PJ_ICE_CAND_TYPE_HOST;
		} else if (candidate->type == AST_RTP_ICE_CANDIDATE_TYPE_SRFLX) {
			candidates[cand_cnt].type = PJ_ICE_CAND_TYPE_SRFLX;
		} else if (candidate->type == AST_RTP_ICE_CANDIDATE_TYPE_RELAYED) {
			candidates[cand_cnt].type = PJ_ICE_CAND_TYPE_RELAYED;
		}

		if (candidate->id == AST_RTP_ICE_COMPONENT_RTP && rtp->turn_rtp) {
			ast_debug(3, "RTP candidate %s (%p)\n", ast_sockaddr_stringify(&candidate->address), instance);
			/* Release the instance lock to avoid deadlock with PJPROJECT group lock */
			ao2_unlock(instance);
			pj_turn_sock_set_perm(rtp->turn_rtp, 1, &candidates[cand_cnt].addr, 1);
			ao2_lock(instance);
		} else if (candidate->id == AST_RTP_ICE_COMPONENT_RTCP && rtp->turn_rtcp) {
			ast_debug(3, "RTCP candidate %s (%p)\n", ast_sockaddr_stringify(&candidate->address), instance);
			/* Release the instance lock to avoid deadlock with PJPROJECT group lock */
			ao2_unlock(instance);
			pj_turn_sock_set_perm(rtp->turn_rtcp, 1, &candidates[cand_cnt].addr, 1);
			ao2_lock(instance);
		}

		cand_cnt++;
		ao2_ref(candidate, -1);
	}

	ao2_iterator_destroy(&i);

	if (cand_cnt < ao2_container_count(rtp->ice_active_remote_candidates)) {
		ast_log(LOG_WARNING, "Lost %d ICE candidates. Consider increasing PJ_ICE_MAX_CAND in PJSIP (%p)\n",
			ao2_container_count(rtp->ice_active_remote_candidates) - cand_cnt, instance);
	}

	if (!has_rtp) {
		ast_log(LOG_WARNING, "No RTP candidates; skipping ICE checklist (%p)\n", instance);
	}

	/* If we're only dealing with one ICE component, then we don't care about the lack of RTCP candidates */
	if (!has_rtcp && rtp->ice_num_components > 1) {
		ast_log(LOG_WARNING, "No RTCP candidates; skipping ICE checklist (%p)\n", instance);
	}

	if (rtp->ice && has_rtp && (has_rtcp || rtp->ice_num_components == 1)) {
		pj_status_t res;
		char reason[80];
		struct ice_wrap *ice;

		/* Release the instance lock to avoid deadlock with PJPROJECT group lock */
		ice = rtp->ice;
		ao2_ref(ice, +1);
		ao2_unlock(instance);
		res = pj_ice_sess_create_check_list(ice->real_ice, &ufrag, &passwd, cand_cnt, &candidates[0]);
		if (res == PJ_SUCCESS) {
			ast_debug(3, "Successfully created ICE checklist (%p)\n", instance);
			ast_test_suite_event_notify("ICECHECKLISTCREATE", "Result: SUCCESS");
			pj_ice_sess_start_check(ice->real_ice);
			pj_timer_heap_poll(timer_heap, NULL);
			ao2_ref(ice, -1);
			ao2_lock(instance);
			rtp->strict_rtp_state = STRICT_RTP_OPEN;
			return;
		}
		ao2_ref(ice, -1);
		ao2_lock(instance);

		pj_strerror(res, reason, sizeof(reason));
		ast_log(LOG_WARNING, "Failed to create ICE session check list: %s (%p)\n", reason, instance);
	}

	ast_test_suite_event_notify("ICECHECKLISTCREATE", "Result: FAILURE");

	/* even though create check list failed don't stop ice as
	   it might still work */
	/* however we do need to reset remote candidates since
	   this function may be re-entered */
	ao2_ref(rtp->ice_active_remote_candidates, -1);
	rtp->ice_active_remote_candidates = NULL;
	if (rtp->ice) {
		rtp->ice->real_ice->rcand_cnt = rtp->ice->real_ice->clist.count = 0;
	}
}

/*! \pre instance is locked */
static const char *ast_rtp_ice_get_ufrag(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	return rtp->local_ufrag;
}

/*! \pre instance is locked */
static const char *ast_rtp_ice_get_password(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	return rtp->local_passwd;
}

/*! \pre instance is locked */
static struct ao2_container *ast_rtp_ice_get_local_candidates(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (rtp->ice_local_candidates) {
		ao2_ref(rtp->ice_local_candidates, +1);
	}

	return rtp->ice_local_candidates;
}

/*! \pre instance is locked */
static void ast_rtp_ice_lite(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (!rtp->ice) {
		return;
	}

	pj_thread_register_check();

	pj_ice_sess_change_role(rtp->ice->real_ice, PJ_ICE_SESS_ROLE_CONTROLLING);
}

/*! \pre instance is locked */
static void ast_rtp_ice_set_role(struct ast_rtp_instance *instance, enum ast_rtp_ice_role role)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	ast_debug(3, "Set role to %s (%p)\n",
		role == AST_RTP_ICE_ROLE_CONTROLLED ? "CONTROLLED" : "CONTROLLING", instance);

	if (!rtp->ice) {
		ast_debug(3, "Set role failed; no ice instance (%p)\n", instance);
		return;
	}

	rtp->role = role;

	if (!rtp->ice->real_ice->is_nominating && !rtp->ice->real_ice->is_complete) {
		pj_thread_register_check();

		pj_ice_sess_change_role(rtp->ice->real_ice, role == AST_RTP_ICE_ROLE_CONTROLLED ?
			PJ_ICE_SESS_ROLE_CONTROLLED : PJ_ICE_SESS_ROLE_CONTROLLING);
	} else {
		ast_debug(3, "Not setting ICE role because state is %s\n", rtp->ice->real_ice->is_nominating ? "nominating" : "complete" );
	}
}

/*! \pre instance is locked */
static void ast_rtp_ice_add_cand(struct ast_rtp_instance *instance, struct ast_rtp *rtp,
	unsigned comp_id, unsigned transport_id, pj_ice_cand_type type, pj_uint16_t local_pref,
	const pj_sockaddr_t *addr, const pj_sockaddr_t *base_addr, const pj_sockaddr_t *rel_addr,
	int addr_len)
{
	pj_str_t foundation;
	struct ast_rtp_engine_ice_candidate *candidate, *existing;
	struct ice_wrap *ice;
	char address[PJ_INET6_ADDRSTRLEN];
	pj_status_t status;

	if (!rtp->ice) {
		return;
	}

	pj_thread_register_check();

	pj_ice_calc_foundation(rtp->ice->real_ice->pool, &foundation, type, addr);

	if (!rtp->ice_local_candidates) {
		rtp->ice_local_candidates = ao2_container_alloc_list(AO2_ALLOC_OPT_LOCK_MUTEX, 0,
			NULL, ice_candidate_cmp);
		if (!rtp->ice_local_candidates) {
			return;
		}
	}

	if (!(candidate = ao2_alloc(sizeof(*candidate), ast_rtp_ice_candidate_destroy))) {
		return;
	}

	candidate->foundation = ast_strndup(pj_strbuf(&foundation), pj_strlen(&foundation));
	candidate->id = comp_id;
	candidate->transport = ast_strdup("UDP");

	ast_sockaddr_parse(&candidate->address, pj_sockaddr_print(addr, address, sizeof(address), 0), 0);
	ast_sockaddr_set_port(&candidate->address, pj_sockaddr_get_port(addr));

	if (rel_addr) {
		ast_sockaddr_parse(&candidate->relay_address, pj_sockaddr_print(rel_addr, address, sizeof(address), 0), 0);
		ast_sockaddr_set_port(&candidate->relay_address, pj_sockaddr_get_port(rel_addr));
	}

	if (type == PJ_ICE_CAND_TYPE_HOST) {
		candidate->type = AST_RTP_ICE_CANDIDATE_TYPE_HOST;
	} else if (type == PJ_ICE_CAND_TYPE_SRFLX) {
		candidate->type = AST_RTP_ICE_CANDIDATE_TYPE_SRFLX;
	} else if (type == PJ_ICE_CAND_TYPE_RELAYED) {
		candidate->type = AST_RTP_ICE_CANDIDATE_TYPE_RELAYED;
	}

	if ((existing = ao2_find(rtp->ice_local_candidates, candidate, OBJ_POINTER))) {
		ao2_ref(existing, -1);
		ao2_ref(candidate, -1);
		return;
	}

	/* Release the instance lock to avoid deadlock with PJPROJECT group lock */
	ice = rtp->ice;
	ao2_ref(ice, +1);
	ao2_unlock(instance);
	status = pj_ice_sess_add_cand(ice->real_ice, comp_id, transport_id, type, local_pref,
		&foundation, addr, base_addr, rel_addr, addr_len, NULL);
	ao2_ref(ice, -1);
	ao2_lock(instance);
	if (!rtp->ice || status != PJ_SUCCESS) {
		ao2_ref(candidate, -1);
		return;
	}

	/* By placing the candidate into the ICE session it will have produced the priority, so update the local candidate with it */
	candidate->priority = rtp->ice->real_ice->lcand[rtp->ice->real_ice->lcand_cnt - 1].prio;

	ao2_link(rtp->ice_local_candidates, candidate);
	ao2_ref(candidate, -1);
}

/* PJPROJECT TURN callback */
static void ast_rtp_on_turn_rx_rtp_data(pj_turn_sock *turn_sock, void *pkt, unsigned pkt_len, const pj_sockaddr_t *peer_addr, unsigned addr_len)
{
	struct ast_rtp_instance *instance = pj_turn_sock_get_user_data(turn_sock);
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ice_wrap *ice;
	pj_status_t status;

	ao2_lock(instance);
	ice = ao2_bump(rtp->ice);
	ao2_unlock(instance);

	if (ice) {
		status = pj_ice_sess_on_rx_pkt(ice->real_ice, AST_RTP_ICE_COMPONENT_RTP,
			TRANSPORT_TURN_RTP, pkt, pkt_len, peer_addr, addr_len);
		ao2_ref(ice, -1);
		if (status != PJ_SUCCESS) {
			char buf[100];

			pj_strerror(status, buf, sizeof(buf));
			ast_log(LOG_WARNING, "PJ ICE Rx error status code: %d '%s'.\n",
				(int)status, buf);
			return;
		}
		if (!rtp->rtp_passthrough) {
			return;
		}
		rtp->rtp_passthrough = 0;
	}

	ast_sendto(rtp->s, pkt, pkt_len, 0, &rtp->rtp_loop);
}

/* PJPROJECT TURN callback */
static void ast_rtp_on_turn_rtp_state(pj_turn_sock *turn_sock, pj_turn_state_t old_state, pj_turn_state_t new_state)
{
	struct ast_rtp_instance *instance = pj_turn_sock_get_user_data(turn_sock);
	struct ast_rtp *rtp;

	/* If this is a leftover from an already notified RTP instance just ignore the state change */
	if (!instance) {
		return;
	}

	rtp = ast_rtp_instance_get_data(instance);

	ao2_lock(instance);

	/* We store the new state so the other thread can actually handle it */
	rtp->turn_state = new_state;
	ast_cond_signal(&rtp->cond);

	if (new_state == PJ_TURN_STATE_DESTROYING) {
		pj_turn_sock_set_user_data(rtp->turn_rtp, NULL);
		rtp->turn_rtp = NULL;
	}

	ao2_unlock(instance);
}

/* RTP TURN Socket interface declaration */
static pj_turn_sock_cb ast_rtp_turn_rtp_sock_cb = {
	.on_rx_data = ast_rtp_on_turn_rx_rtp_data,
	.on_state = ast_rtp_on_turn_rtp_state,
};

/* PJPROJECT TURN callback */
static void ast_rtp_on_turn_rx_rtcp_data(pj_turn_sock *turn_sock, void *pkt, unsigned pkt_len, const pj_sockaddr_t *peer_addr, unsigned addr_len)
{
	struct ast_rtp_instance *instance = pj_turn_sock_get_user_data(turn_sock);
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ice_wrap *ice;
	pj_status_t status;

	ao2_lock(instance);
	ice = ao2_bump(rtp->ice);
	ao2_unlock(instance);

	if (ice) {
		status = pj_ice_sess_on_rx_pkt(ice->real_ice, AST_RTP_ICE_COMPONENT_RTCP,
			TRANSPORT_TURN_RTCP, pkt, pkt_len, peer_addr, addr_len);
		ao2_ref(ice, -1);
		if (status != PJ_SUCCESS) {
			char buf[100];

			pj_strerror(status, buf, sizeof(buf));
			ast_log(LOG_WARNING, "PJ ICE Rx error status code: %d '%s'.\n",
				(int)status, buf);
			return;
		}
		if (!rtp->rtcp_passthrough) {
			return;
		}
		rtp->rtcp_passthrough = 0;
	}

	ast_sendto(rtp->rtcp->s, pkt, pkt_len, 0, &rtp->rtcp_loop);
}

/* PJPROJECT TURN callback */
static void ast_rtp_on_turn_rtcp_state(pj_turn_sock *turn_sock, pj_turn_state_t old_state, pj_turn_state_t new_state)
{
	struct ast_rtp_instance *instance = pj_turn_sock_get_user_data(turn_sock);
	struct ast_rtp *rtp;

	/* If this is a leftover from an already destroyed RTP instance just ignore the state change */
	if (!instance) {
		return;
	}

	rtp = ast_rtp_instance_get_data(instance);

	ao2_lock(instance);

	/* We store the new state so the other thread can actually handle it */
	rtp->turn_state = new_state;
	ast_cond_signal(&rtp->cond);

	if (new_state == PJ_TURN_STATE_DESTROYING) {
		pj_turn_sock_set_user_data(rtp->turn_rtcp, NULL);
		rtp->turn_rtcp = NULL;
	}

	ao2_unlock(instance);
}

/* RTCP TURN Socket interface declaration */
static pj_turn_sock_cb ast_rtp_turn_rtcp_sock_cb = {
	.on_rx_data = ast_rtp_on_turn_rx_rtcp_data,
	.on_state = ast_rtp_on_turn_rtcp_state,
};

/*! \brief Worker thread for ioqueue and timerheap */
static int ioqueue_worker_thread(void *data)
{
	struct ast_rtp_ioqueue_thread *ioqueue = data;

	while (!ioqueue->terminate) {
		const pj_time_val delay = {0, 10};

		pj_ioqueue_poll(ioqueue->ioqueue, &delay);

		pj_timer_heap_poll(ioqueue->timerheap, NULL);
	}

	return 0;
}

/*! \brief Destroyer for ioqueue thread */
static void rtp_ioqueue_thread_destroy(struct ast_rtp_ioqueue_thread *ioqueue)
{
	if (ioqueue->thread) {
		ioqueue->terminate = 1;
		pj_thread_join(ioqueue->thread);
		pj_thread_destroy(ioqueue->thread);
	}

	if (ioqueue->pool) {
		/* This mimics the behavior of pj_pool_safe_release
		 * which was introduced in pjproject 2.6.
		 */
		pj_pool_t *temp_pool = ioqueue->pool;

		ioqueue->pool = NULL;
		pj_pool_release(temp_pool);
	}

	ast_free(ioqueue);
}

/*! \brief Removal function for ioqueue thread, determines if it should be terminated and destroyed */
static void rtp_ioqueue_thread_remove(struct ast_rtp_ioqueue_thread *ioqueue)
{
	int destroy = 0;

	/* If nothing is using this ioqueue thread destroy it */
	AST_LIST_LOCK(&ioqueues);
	if ((ioqueue->count - 2) == 0) {
		destroy = 1;
		AST_LIST_REMOVE(&ioqueues, ioqueue, next);
	}
	AST_LIST_UNLOCK(&ioqueues);

	if (!destroy) {
		return;
	}

	rtp_ioqueue_thread_destroy(ioqueue);
}

/*! \brief Finder and allocator for an ioqueue thread */
static struct ast_rtp_ioqueue_thread *rtp_ioqueue_thread_get_or_create(void)
{
	struct ast_rtp_ioqueue_thread *ioqueue;
	pj_lock_t *lock;

	AST_LIST_LOCK(&ioqueues);

	/* See if an ioqueue thread exists that can handle more */
	AST_LIST_TRAVERSE(&ioqueues, ioqueue, next) {
		if ((ioqueue->count + 2) < PJ_IOQUEUE_MAX_HANDLES) {
			break;
		}
	}

	/* If we found one bump it up and return it */
	if (ioqueue) {
		ioqueue->count += 2;
		goto end;
	}

	ioqueue = ast_calloc(1, sizeof(*ioqueue));
	if (!ioqueue) {
		goto end;
	}

	ioqueue->pool = pj_pool_create(&cachingpool.factory, "rtp", 512, 512, NULL);

	/* We use a timer on the ioqueue thread for TURN so that two threads aren't operating
	 * on a session at the same time
	 */
	if (pj_timer_heap_create(ioqueue->pool, 4, &ioqueue->timerheap) != PJ_SUCCESS) {
		goto fatal;
	}

	if (pj_lock_create_recursive_mutex(ioqueue->pool, "rtp%p", &lock) != PJ_SUCCESS) {
		goto fatal;
	}

	pj_timer_heap_set_lock(ioqueue->timerheap, lock, PJ_TRUE);

	if (pj_ioqueue_create(ioqueue->pool, PJ_IOQUEUE_MAX_HANDLES, &ioqueue->ioqueue) != PJ_SUCCESS) {
		goto fatal;
	}

	if (pj_thread_create(ioqueue->pool, "ice", &ioqueue_worker_thread, ioqueue, 0, 0, &ioqueue->thread) != PJ_SUCCESS) {
		goto fatal;
	}

	AST_LIST_INSERT_HEAD(&ioqueues, ioqueue, next);

	/* Since this is being returned to an active session the count always starts at 2 */
	ioqueue->count = 2;

	goto end;

fatal:
	rtp_ioqueue_thread_destroy(ioqueue);
	ioqueue = NULL;

end:
	AST_LIST_UNLOCK(&ioqueues);
	return ioqueue;
}

/*! \pre instance is locked */
static void ast_rtp_ice_turn_request(struct ast_rtp_instance *instance, enum ast_rtp_ice_component_type component,
		enum ast_transport transport, const char *server, unsigned int port, const char *username, const char *password)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	pj_turn_sock **turn_sock;
	const pj_turn_sock_cb *turn_cb;
	pj_turn_tp_type conn_type;
	int conn_transport;
	pj_stun_auth_cred cred = { 0, };
	pj_str_t turn_addr;
	struct ast_sockaddr addr = { { 0, } };
	pj_stun_config stun_config;
	struct timeval wait = ast_tvadd(ast_tvnow(), ast_samp2tv(TURN_STATE_WAIT_TIME, 1000));
	struct timespec ts = { .tv_sec = wait.tv_sec, .tv_nsec = wait.tv_usec * 1000, };
	pj_turn_session_info info;
	struct ast_sockaddr local, loop;
	pj_status_t status;
	pj_turn_sock_cfg turn_sock_cfg;
	struct ice_wrap *ice;

	ast_rtp_instance_get_local_address(instance, &local);
	if (ast_sockaddr_is_ipv4(&local)) {
		ast_sockaddr_parse(&loop, "127.0.0.1", PARSE_PORT_FORBID);
	} else {
		ast_sockaddr_parse(&loop, "::1", PARSE_PORT_FORBID);
	}

	/* Determine what component we are requesting a TURN session for */
	if (component == AST_RTP_ICE_COMPONENT_RTP) {
		turn_sock = &rtp->turn_rtp;
		turn_cb = &ast_rtp_turn_rtp_sock_cb;
		conn_transport = TRANSPORT_TURN_RTP;
		ast_sockaddr_set_port(&loop, ast_sockaddr_port(&local));
	} else if (component == AST_RTP_ICE_COMPONENT_RTCP) {
		turn_sock = &rtp->turn_rtcp;
		turn_cb = &ast_rtp_turn_rtcp_sock_cb;
		conn_transport = TRANSPORT_TURN_RTCP;
		ast_sockaddr_set_port(&loop, ast_sockaddr_port(&rtp->rtcp->us));
	} else {
		return;
	}

	if (transport == AST_TRANSPORT_UDP) {
		conn_type = PJ_TURN_TP_UDP;
	} else if (transport == AST_TRANSPORT_TCP) {
		conn_type = PJ_TURN_TP_TCP;
	} else {
		ast_assert(0);
		return;
	}

	ast_sockaddr_parse(&addr, server, PARSE_PORT_FORBID);

	if (*turn_sock) {
		rtp->turn_state = PJ_TURN_STATE_NULL;

		/* Release the instance lock to avoid deadlock with PJPROJECT group lock */
		ao2_unlock(instance);
		pj_turn_sock_destroy(*turn_sock);
		ao2_lock(instance);
		while (rtp->turn_state != PJ_TURN_STATE_DESTROYING) {
			ast_cond_timedwait(&rtp->cond, ao2_object_get_lockaddr(instance), &ts);
		}
	}

	if (component == AST_RTP_ICE_COMPONENT_RTP && !rtp->ioqueue) {
		/*
		 * We cannot hold the instance lock because we could wait
		 * for the ioqueue thread to die and we might deadlock as
		 * a result.
		 */
		ao2_unlock(instance);
		rtp->ioqueue = rtp_ioqueue_thread_get_or_create();
		ao2_lock(instance);
		if (!rtp->ioqueue) {
			return;
		}
	}

	pj_stun_config_init(&stun_config, &cachingpool.factory, 0, rtp->ioqueue->ioqueue, rtp->ioqueue->timerheap);

	/* Use ICE session group lock for TURN session to avoid deadlock */
	pj_turn_sock_cfg_default(&turn_sock_cfg);
	ice = rtp->ice;
	if (ice) {
		turn_sock_cfg.grp_lock = ice->real_ice->grp_lock;
		ao2_ref(ice, +1);
	}

	/* Release the instance lock to avoid deadlock with PJPROJECT group lock */
	ao2_unlock(instance);
	status = pj_turn_sock_create(&stun_config,
		ast_sockaddr_is_ipv4(&addr) ? pj_AF_INET() : pj_AF_INET6(), conn_type,
		turn_cb, &turn_sock_cfg, instance, turn_sock);
	ao2_cleanup(ice);
	if (status != PJ_SUCCESS) {
		ast_log(LOG_WARNING, "Could not create a TURN client socket\n");
		ao2_lock(instance);
		return;
	}

	cred.type = PJ_STUN_AUTH_CRED_STATIC;
	pj_strset2(&cred.data.static_cred.username, (char*)username);
	cred.data.static_cred.data_type = PJ_STUN_PASSWD_PLAIN;
	pj_strset2(&cred.data.static_cred.data, (char*)password);

	pj_turn_sock_alloc(*turn_sock, pj_cstr(&turn_addr, server), port, NULL, &cred, NULL);
	ao2_lock(instance);

	/*
	 * Because the TURN socket is asynchronous and we are synchronous we need to
	 * wait until it is done
	 */
	while (rtp->turn_state < PJ_TURN_STATE_READY) {
		ast_cond_timedwait(&rtp->cond, ao2_object_get_lockaddr(instance), &ts);
	}

	/* If a TURN session was allocated add it as a candidate */
	if (rtp->turn_state != PJ_TURN_STATE_READY) {
		return;
	}

	pj_turn_sock_get_info(*turn_sock, &info);

	ast_rtp_ice_add_cand(instance, rtp, component, conn_transport,
		PJ_ICE_CAND_TYPE_RELAYED, 65535, &info.relay_addr, &info.relay_addr,
		&info.mapped_addr, pj_sockaddr_get_len(&info.relay_addr));

	if (component == AST_RTP_ICE_COMPONENT_RTP) {
		ast_sockaddr_copy(&rtp->rtp_loop, &loop);
	} else if (component == AST_RTP_ICE_COMPONENT_RTCP) {
		ast_sockaddr_copy(&rtp->rtcp_loop, &loop);
	}
}

static char *generate_random_string(char *buf, size_t size)
{
        long val[4];
        int x;

        for (x=0; x<4; x++) {
                val[x] = ast_random();
	}
        snprintf(buf, size, "%08lx%08lx%08lx%08lx", (long unsigned)val[0], (long unsigned)val[1], (long unsigned)val[2], (long unsigned)val[3]);

        return buf;
}

/*! \pre instance is locked */
static void ast_rtp_ice_change_components(struct ast_rtp_instance *instance, int num_components)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	/* Don't do anything if ICE is unsupported or if we're not changing the
	 * number of components
	 */
	if (!icesupport || !rtp->ice || rtp->ice_num_components == num_components) {
		return;
	}

	rtp->ice_num_components = num_components;
	ice_reset_session(instance);
}

/* ICE RTP Engine interface declaration */
static struct ast_rtp_engine_ice ast_rtp_ice = {
	.set_authentication = ast_rtp_ice_set_authentication,
	.add_remote_candidate = ast_rtp_ice_add_remote_candidate,
	.start = ast_rtp_ice_start,
	.stop = ast_rtp_ice_stop,
	.get_ufrag = ast_rtp_ice_get_ufrag,
	.get_password = ast_rtp_ice_get_password,
	.get_local_candidates = ast_rtp_ice_get_local_candidates,
	.ice_lite = ast_rtp_ice_lite,
	.set_role = ast_rtp_ice_set_role,
	.turn_request = ast_rtp_ice_turn_request,
	.change_components = ast_rtp_ice_change_components,
};
#endif

#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
static int dtls_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
	/* We don't want to actually verify the certificate so just accept what they have provided */
	return 1;
}

static int dtls_details_initialize(struct dtls_details *dtls, SSL_CTX *ssl_ctx,
	enum ast_rtp_dtls_setup setup)
{
	dtls->dtls_setup = setup;

	if (!(dtls->ssl = SSL_new(ssl_ctx))) {
		ast_log(LOG_ERROR, "Failed to allocate memory for SSL\n");
		goto error;
	}

	if (!(dtls->read_bio = BIO_new(BIO_s_mem()))) {
		ast_log(LOG_ERROR, "Failed to allocate memory for inbound SSL traffic\n");
		goto error;
	}
	BIO_set_mem_eof_return(dtls->read_bio, -1);

	if (!(dtls->write_bio = BIO_new(BIO_s_mem()))) {
		ast_log(LOG_ERROR, "Failed to allocate memory for outbound SSL traffic\n");
		goto error;
	}
	BIO_set_mem_eof_return(dtls->write_bio, -1);

	SSL_set_bio(dtls->ssl, dtls->read_bio, dtls->write_bio);

	if (dtls->dtls_setup == AST_RTP_DTLS_SETUP_PASSIVE) {
		SSL_set_accept_state(dtls->ssl);
	} else {
		SSL_set_connect_state(dtls->ssl);
	}
	dtls->connection = AST_RTP_DTLS_CONNECTION_NEW;

	return 0;

error:
	if (dtls->read_bio) {
		BIO_free(dtls->read_bio);
		dtls->read_bio = NULL;
	}

	if (dtls->write_bio) {
		BIO_free(dtls->write_bio);
		dtls->write_bio = NULL;
	}

	if (dtls->ssl) {
		SSL_free(dtls->ssl);
		dtls->ssl = NULL;
	}
	return -1;
}

static int dtls_setup_rtcp(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (!rtp->ssl_ctx || !rtp->rtcp) {
		return 0;
	}

	return dtls_details_initialize(&rtp->rtcp->dtls, rtp->ssl_ctx, rtp->dtls.dtls_setup);
}

static const SSL_METHOD *get_dtls_method(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10002000L || defined(LIBRESSL_VERSION_NUMBER)
	return DTLSv1_method();
#else
	return DTLS_method();
#endif
}

struct dtls_cert_info {
	EVP_PKEY *private_key;
	X509 *certificate;
};

static void configure_dhparams(const struct ast_rtp *rtp, const struct ast_rtp_dtls_cfg *dtls_cfg)
{
#if !defined(OPENSSL_NO_ECDH) && (OPENSSL_VERSION_NUMBER >= 0x10000000L) && (OPENSSL_VERSION_NUMBER < 0x10100000L)
	EC_KEY *ecdh;
#endif

#ifndef OPENSSL_NO_DH
	if (!ast_strlen_zero(dtls_cfg->pvtfile)) {
		BIO *bio = BIO_new_file(dtls_cfg->pvtfile, "r");
		if (bio) {
			DH *dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
			if (dh) {
				if (SSL_CTX_set_tmp_dh(rtp->ssl_ctx, dh)) {
					long options = SSL_OP_CIPHER_SERVER_PREFERENCE |
						SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE;
					options = SSL_CTX_set_options(rtp->ssl_ctx, options);
					ast_verb(2, "DTLS DH initialized, PFS enabled\n");
				}
				DH_free(dh);
			}
			BIO_free(bio);
		}
	}
#endif /* !OPENSSL_NO_DH */

#if !defined(OPENSSL_NO_ECDH) && (OPENSSL_VERSION_NUMBER >= 0x10000000L) && (OPENSSL_VERSION_NUMBER < 0x10100000L)
	/* enables AES-128 ciphers, to get AES-256 use NID_secp384r1 */
	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (ecdh) {
		if (SSL_CTX_set_tmp_ecdh(rtp->ssl_ctx, ecdh)) {
			#ifndef SSL_CTRL_SET_ECDH_AUTO
				#define SSL_CTRL_SET_ECDH_AUTO 94
			#endif
			/* SSL_CTX_set_ecdh_auto(rtp->ssl_ctx, on); requires OpenSSL 1.0.2 which wraps: */
			if (SSL_CTX_ctrl(rtp->ssl_ctx, SSL_CTRL_SET_ECDH_AUTO, 1, NULL)) {
				ast_verb(2, "DTLS ECDH initialized (automatic), faster PFS enabled\n");
			} else {
				ast_verb(2, "DTLS ECDH initialized (secp256r1), faster PFS enabled\n");
			}
		}
		EC_KEY_free(ecdh);
	}
#endif /* !OPENSSL_NO_ECDH */
}

#if !defined(OPENSSL_NO_ECDH) && (OPENSSL_VERSION_NUMBER >= 0x10000000L)

static int create_ephemeral_ec_keypair(EVP_PKEY **keypair)
{
	EC_KEY *eckey = NULL;
	EC_GROUP *group = NULL;

	group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if (!group) {
		goto error;
	}

	EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
	EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_UNCOMPRESSED);

	eckey = EC_KEY_new();
	if (!eckey) {
		goto error;
	}

	if (!EC_KEY_set_group(eckey, group)) {
		goto error;
	}

	if (!EC_KEY_generate_key(eckey)) {
		goto error;
	}

	*keypair = EVP_PKEY_new();
	if (!*keypair) {
		goto error;
	}

	EVP_PKEY_assign_EC_KEY(*keypair, eckey);
	EC_GROUP_free(group);

	return 0;

error:
	EC_KEY_free(eckey);
	EC_GROUP_free(group);

	return -1;
}

/* From OpenSSL's x509 command */
#define SERIAL_RAND_BITS 159

static int create_ephemeral_certificate(EVP_PKEY *keypair, X509 **certificate)
{
	X509 *cert = NULL;
	BIGNUM *serial = NULL;
	X509_NAME *name = NULL;

	cert = X509_new();
	if (!cert) {
		goto error;
	}

	if (!X509_set_version(cert, 2)) {
		goto error;
	}

	/* Set the public key */
	X509_set_pubkey(cert, keypair);

	/* Generate a random serial number */
	if (!(serial = BN_new())
	   || !BN_rand(serial, SERIAL_RAND_BITS, -1, 0)
	   || !BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(cert))) {
		goto error;
	}

	/*
	 * Validity period - Current Chrome & Firefox make it 31 days starting
	 * with yesterday at the current time, so we will do the same.
	 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	if (!X509_time_adj_ex(X509_get_notBefore(cert), -1, 0, NULL)
	   || !X509_time_adj_ex(X509_get_notAfter(cert), 30, 0, NULL)) {
		goto error;
	}
#else
	if (!X509_time_adj_ex(X509_getm_notBefore(cert), -1, 0, NULL)
	   || !X509_time_adj_ex(X509_getm_notAfter(cert), 30, 0, NULL)) {
		goto error;
	}
#endif

	/* Set the name and issuer */
	if (!(name = X509_get_subject_name(cert))
	   || !X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC,
									  (unsigned char *) "asterisk", -1, -1, 0)
	   || !X509_set_issuer_name(cert, name)) {
		goto error;
	}

	/* Sign it */
	if (!X509_sign(cert, keypair, EVP_sha256())) {
		goto error;
	}

	*certificate = cert;

	return 0;

error:
	BN_free(serial);
	X509_free(cert);

	return -1;
}

static int create_certificate_ephemeral(struct ast_rtp_instance *instance,
										const struct ast_rtp_dtls_cfg *dtls_cfg,
										struct dtls_cert_info *cert_info)
{
	/* Make sure these are initialized */
	cert_info->private_key = NULL;
	cert_info->certificate = NULL;

	if (create_ephemeral_ec_keypair(&cert_info->private_key)) {
		ast_log(LOG_ERROR, "Failed to create ephemeral ECDSA keypair\n");
		goto error;
	}

	if (create_ephemeral_certificate(cert_info->private_key, &cert_info->certificate)) {
		ast_log(LOG_ERROR, "Failed to create ephemeral X509 certificate\n");
		goto error;
	}

	return 0;

  error:
	X509_free(cert_info->certificate);
	EVP_PKEY_free(cert_info->private_key);

	return -1;
}

#else

static int create_certificate_ephemeral(struct ast_rtp_instance *instance,
										const struct ast_rtp_dtls_cfg *dtls_cfg,
										struct dtls_cert_info *cert_info)
{
	ast_log(LOG_ERROR, "Your version of OpenSSL does not support ECDSA keys\n");
	return -1;
}

#endif /* !OPENSSL_NO_ECDH */

static int create_certificate_from_file(struct ast_rtp_instance *instance,
										const struct ast_rtp_dtls_cfg *dtls_cfg,
										struct dtls_cert_info *cert_info)
{
	FILE *fp;
	BIO *certbio = NULL;
	EVP_PKEY *private_key = NULL;
	X509 *cert = NULL;
	char *private_key_file = ast_strlen_zero(dtls_cfg->pvtfile) ? dtls_cfg->certfile : dtls_cfg->pvtfile;

	fp = fopen(private_key_file, "r");
	if (!fp) {
		ast_log(LOG_ERROR, "Failed to read private key from file '%s': %s\n", private_key_file, strerror(errno));
		goto error;
	}

	if (!PEM_read_PrivateKey(fp, &private_key, NULL, NULL)) {
		ast_log(LOG_ERROR, "Failed to read private key from PEM file '%s'\n", private_key_file);
		fclose(fp);
		goto error;
	}

	if (fclose(fp)) {
		ast_log(LOG_ERROR, "Failed to close private key file '%s': %s\n", private_key_file, strerror(errno));
		goto error;
	}

	certbio = BIO_new(BIO_s_file());
	if (!certbio) {
		ast_log(LOG_ERROR, "Failed to allocate memory for certificate fingerprinting on RTP instance '%p'\n",
				instance);
		goto error;
	}

	if (!BIO_read_filename(certbio, dtls_cfg->certfile)
	   || !(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
		ast_log(LOG_ERROR, "Failed to read certificate from file '%s'\n", dtls_cfg->certfile);
		goto error;
	}

	cert_info->private_key = private_key;
	cert_info->certificate = cert;

	BIO_free_all(certbio);

	return 0;

error:
	X509_free(cert);
	BIO_free_all(certbio);
	EVP_PKEY_free(private_key);

	return -1;
}

static int load_dtls_certificate(struct ast_rtp_instance *instance,
								 const struct ast_rtp_dtls_cfg *dtls_cfg,
								 struct dtls_cert_info *cert_info)
{
	if (dtls_cfg->ephemeral_cert) {
		return create_certificate_ephemeral(instance, dtls_cfg, cert_info);
	} else if (!ast_strlen_zero(dtls_cfg->certfile)) {
		return create_certificate_from_file(instance, dtls_cfg, cert_info);
	} else {
		return -1;
	}
}

/*! \pre instance is locked */
static int ast_rtp_dtls_set_configuration(struct ast_rtp_instance *instance, const struct ast_rtp_dtls_cfg *dtls_cfg)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct dtls_cert_info cert_info = { 0 };
	int res;

	if (!dtls_cfg->enabled) {
		return 0;
	}

	if (!ast_rtp_engine_srtp_is_registered()) {
		ast_log(LOG_ERROR, "SRTP support module is not loaded or available. Try loading res_srtp.so.\n");
		return -1;
	}

	if (rtp->ssl_ctx) {
		return 0;
	}

	rtp->ssl_ctx = SSL_CTX_new(get_dtls_method());
	if (!rtp->ssl_ctx) {
		return -1;
	}

	SSL_CTX_set_read_ahead(rtp->ssl_ctx, 1);

	configure_dhparams(rtp, dtls_cfg);

	rtp->dtls_verify = dtls_cfg->verify;

	SSL_CTX_set_verify(rtp->ssl_ctx, (rtp->dtls_verify & AST_RTP_DTLS_VERIFY_FINGERPRINT) || (rtp->dtls_verify & AST_RTP_DTLS_VERIFY_CERTIFICATE) ?
		SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT : SSL_VERIFY_NONE, !(rtp->dtls_verify & AST_RTP_DTLS_VERIFY_CERTIFICATE) ?
		dtls_verify_callback : NULL);

	if (dtls_cfg->suite == AST_AES_CM_128_HMAC_SHA1_80) {
		SSL_CTX_set_tlsext_use_srtp(rtp->ssl_ctx, "SRTP_AES128_CM_SHA1_80");
	} else if (dtls_cfg->suite == AST_AES_CM_128_HMAC_SHA1_32) {
		SSL_CTX_set_tlsext_use_srtp(rtp->ssl_ctx, "SRTP_AES128_CM_SHA1_32");
	} else {
		ast_log(LOG_ERROR, "Unsupported suite specified for DTLS-SRTP on RTP instance '%p'\n", instance);
		return -1;
	}

	rtp->local_hash = dtls_cfg->hash;

	if (!load_dtls_certificate(instance, dtls_cfg, &cert_info)) {
		const EVP_MD *type;
		unsigned int size, i;
		unsigned char fingerprint[EVP_MAX_MD_SIZE];
		char *local_fingerprint = rtp->local_fingerprint;

		if (!SSL_CTX_use_certificate(rtp->ssl_ctx, cert_info.certificate)) {
			ast_log(LOG_ERROR, "Specified certificate for RTP instance '%p' could not be used\n",
					instance);
			return -1;
		}

		if (!SSL_CTX_use_PrivateKey(rtp->ssl_ctx, cert_info.private_key)
		    || !SSL_CTX_check_private_key(rtp->ssl_ctx)) {
			ast_log(LOG_ERROR, "Specified private key for RTP instance '%p' could not be used\n",
					instance);
			return -1;
		}

		if (rtp->local_hash == AST_RTP_DTLS_HASH_SHA1) {
			type = EVP_sha1();
		} else if (rtp->local_hash == AST_RTP_DTLS_HASH_SHA256) {
			type = EVP_sha256();
		} else {
			ast_log(LOG_ERROR, "Unsupported fingerprint hash type on RTP instance '%p'\n",
				instance);
			return -1;
		}

		if (!X509_digest(cert_info.certificate, type, fingerprint, &size) || !size) {
			ast_log(LOG_ERROR, "Could not produce fingerprint from certificate for RTP instance '%p'\n",
					instance);
			return -1;
		}

		for (i = 0; i < size; i++) {
			sprintf(local_fingerprint, "%02hhX:", fingerprint[i]);
			local_fingerprint += 3;
		}

		*(local_fingerprint - 1) = 0;

		EVP_PKEY_free(cert_info.private_key);
		X509_free(cert_info.certificate);
	}

	if (!ast_strlen_zero(dtls_cfg->cipher)) {
		if (!SSL_CTX_set_cipher_list(rtp->ssl_ctx, dtls_cfg->cipher)) {
			ast_log(LOG_ERROR, "Invalid cipher specified in cipher list '%s' for RTP instance '%p'\n",
				dtls_cfg->cipher, instance);
			return -1;
		}
	}

	if (!ast_strlen_zero(dtls_cfg->cafile) || !ast_strlen_zero(dtls_cfg->capath)) {
		if (!SSL_CTX_load_verify_locations(rtp->ssl_ctx, S_OR(dtls_cfg->cafile, NULL), S_OR(dtls_cfg->capath, NULL))) {
			ast_log(LOG_ERROR, "Invalid certificate authority file '%s' or path '%s' specified for RTP instance '%p'\n",
				S_OR(dtls_cfg->cafile, ""), S_OR(dtls_cfg->capath, ""), instance);
			return -1;
		}
	}

	rtp->rekey = dtls_cfg->rekey;
	rtp->suite = dtls_cfg->suite;

	res = dtls_details_initialize(&rtp->dtls, rtp->ssl_ctx, dtls_cfg->default_setup);
	if (!res) {
		dtls_setup_rtcp(instance);
	}

	return res;
}

/*! \pre instance is locked */
static int ast_rtp_dtls_active(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	return !rtp->ssl_ctx ? 0 : 1;
}

/*! \pre instance is locked */
static void ast_rtp_dtls_stop(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	SSL *ssl = rtp->dtls.ssl;

	ao2_unlock(instance);
	dtls_srtp_stop_timeout_timer(instance, rtp, 0);
	ao2_lock(instance);

	if (rtp->ssl_ctx) {
		SSL_CTX_free(rtp->ssl_ctx);
		rtp->ssl_ctx = NULL;
	}

	if (rtp->dtls.ssl) {
		SSL_free(rtp->dtls.ssl);
		rtp->dtls.ssl = NULL;
	}

	if (rtp->rtcp) {
		ao2_unlock(instance);
		dtls_srtp_stop_timeout_timer(instance, rtp, 1);
		ao2_lock(instance);

		if (rtp->rtcp->dtls.ssl) {
			if (rtp->rtcp->dtls.ssl != ssl) {
				SSL_free(rtp->rtcp->dtls.ssl);
			}
			rtp->rtcp->dtls.ssl = NULL;
		}
	}
}

/*! \pre instance is locked */
static void ast_rtp_dtls_reset(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (SSL_is_init_finished(rtp->dtls.ssl)) {
		SSL_shutdown(rtp->dtls.ssl);
		rtp->dtls.connection = AST_RTP_DTLS_CONNECTION_NEW;
	}

	if (rtp->rtcp && SSL_is_init_finished(rtp->rtcp->dtls.ssl)) {
		SSL_shutdown(rtp->rtcp->dtls.ssl);
		rtp->rtcp->dtls.connection = AST_RTP_DTLS_CONNECTION_NEW;
	}
}

/*! \pre instance is locked */
static enum ast_rtp_dtls_connection ast_rtp_dtls_get_connection(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	return rtp->dtls.connection;
}

/*! \pre instance is locked */
static enum ast_rtp_dtls_setup ast_rtp_dtls_get_setup(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	return rtp->dtls.dtls_setup;
}

static void dtls_set_setup(enum ast_rtp_dtls_setup *dtls_setup, enum ast_rtp_dtls_setup setup, SSL *ssl)
{
	enum ast_rtp_dtls_setup old = *dtls_setup;

	switch (setup) {
	case AST_RTP_DTLS_SETUP_ACTIVE:
		*dtls_setup = AST_RTP_DTLS_SETUP_PASSIVE;
		break;
	case AST_RTP_DTLS_SETUP_PASSIVE:
		*dtls_setup = AST_RTP_DTLS_SETUP_ACTIVE;
		break;
	case AST_RTP_DTLS_SETUP_ACTPASS:
		/* We can't respond to an actpass setup with actpass ourselves... so respond with active, as we can initiate connections */
		if (*dtls_setup == AST_RTP_DTLS_SETUP_ACTPASS) {
			*dtls_setup = AST_RTP_DTLS_SETUP_ACTIVE;
		}
		break;
	case AST_RTP_DTLS_SETUP_HOLDCONN:
		*dtls_setup = AST_RTP_DTLS_SETUP_HOLDCONN;
		break;
	default:
		/* This should never occur... if it does exit early as we don't know what state things are in */
		return;
	}

	/* If the setup state did not change we go on as if nothing happened */
	if (old == *dtls_setup) {
		return;
	}

	/* If they don't want us to establish a connection wait until later */
	if (*dtls_setup == AST_RTP_DTLS_SETUP_HOLDCONN) {
		return;
	}

	if (*dtls_setup == AST_RTP_DTLS_SETUP_ACTIVE) {
		SSL_set_connect_state(ssl);
	} else if (*dtls_setup == AST_RTP_DTLS_SETUP_PASSIVE) {
		SSL_set_accept_state(ssl);
	} else {
		return;
	}
}

/*! \pre instance is locked */
static void ast_rtp_dtls_set_setup(struct ast_rtp_instance *instance, enum ast_rtp_dtls_setup setup)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (rtp->dtls.ssl) {
		dtls_set_setup(&rtp->dtls.dtls_setup, setup, rtp->dtls.ssl);
	}

	if (rtp->rtcp && rtp->rtcp->dtls.ssl) {
		dtls_set_setup(&rtp->rtcp->dtls.dtls_setup, setup, rtp->rtcp->dtls.ssl);
	}
}

/*! \pre instance is locked */
static void ast_rtp_dtls_set_fingerprint(struct ast_rtp_instance *instance, enum ast_rtp_dtls_hash hash, const char *fingerprint)
{
	char *tmp = ast_strdupa(fingerprint), *value;
	int pos = 0;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (hash != AST_RTP_DTLS_HASH_SHA1 && hash != AST_RTP_DTLS_HASH_SHA256) {
		return;
	}

	rtp->remote_hash = hash;

	while ((value = strsep(&tmp, ":")) && (pos != (EVP_MAX_MD_SIZE - 1))) {
		sscanf(value, "%02hhx", &rtp->remote_fingerprint[pos++]);
	}
}

/*! \pre instance is locked */
static enum ast_rtp_dtls_hash ast_rtp_dtls_get_fingerprint_hash(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	return rtp->local_hash;
}

/*! \pre instance is locked */
static const char *ast_rtp_dtls_get_fingerprint(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	return rtp->local_fingerprint;
}

/* DTLS RTP Engine interface declaration */
static struct ast_rtp_engine_dtls ast_rtp_dtls = {
	.set_configuration = ast_rtp_dtls_set_configuration,
	.active = ast_rtp_dtls_active,
	.stop = ast_rtp_dtls_stop,
	.reset = ast_rtp_dtls_reset,
	.get_connection = ast_rtp_dtls_get_connection,
	.get_setup = ast_rtp_dtls_get_setup,
	.set_setup = ast_rtp_dtls_set_setup,
	.set_fingerprint = ast_rtp_dtls_set_fingerprint,
	.get_fingerprint_hash = ast_rtp_dtls_get_fingerprint_hash,
	.get_fingerprint = ast_rtp_dtls_get_fingerprint,
};

#endif

/* RTP Engine Declaration */
static struct ast_rtp_engine asterisk_rtp_engine = {
	.name = "asterisk",
	.new = ast_rtp_new,
	.destroy = ast_rtp_destroy,
	.dtmf_begin = ast_rtp_dtmf_begin,
	.dtmf_end = ast_rtp_dtmf_end,
	.dtmf_end_with_duration = ast_rtp_dtmf_end_with_duration,
	.dtmf_mode_set = ast_rtp_dtmf_mode_set,
	.dtmf_mode_get = ast_rtp_dtmf_mode_get,
	.update_source = ast_rtp_update_source,
	.change_source = ast_rtp_change_source,
	.write = ast_rtp_write,
	.read = ast_rtp_read,
	.prop_set = ast_rtp_prop_set,
	.fd = ast_rtp_fd,
	.remote_address_set = ast_rtp_remote_address_set,
	.red_init = rtp_red_init,
	.red_buffer = rtp_red_buffer,
	.local_bridge = ast_rtp_local_bridge,
	.get_stat = ast_rtp_get_stat,
	.dtmf_compatible = ast_rtp_dtmf_compatible,
	.stun_request = ast_rtp_stun_request,
	.stop = ast_rtp_stop,
	.qos = ast_rtp_qos_set,
	.sendcng = ast_rtp_sendcng,
#ifdef HAVE_PJPROJECT
	.ice = &ast_rtp_ice,
#endif
#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
	.dtls = &ast_rtp_dtls,
	.activate = ast_rtp_activate,
#endif
	.ssrc_get = ast_rtp_get_ssrc,
	.cname_get = ast_rtp_get_cname,
	.set_remote_ssrc = ast_rtp_set_remote_ssrc,
	.set_stream_num = ast_rtp_set_stream_num,
	.extension_enable = ast_rtp_extension_enable,
	.bundle = ast_rtp_bundle,
};

#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
/*! \pre instance is locked */
static void dtls_perform_handshake(struct ast_rtp_instance *instance, struct dtls_details *dtls, int rtcp)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	/* If we are not acting as a client connecting to the remote side then
	 * don't start the handshake as it will accomplish nothing and would conflict
	 * with the handshake we receive from the remote side.
	 */
	if (!dtls->ssl || (dtls->dtls_setup != AST_RTP_DTLS_SETUP_ACTIVE)) {
		return;
	}

	SSL_do_handshake(dtls->ssl);

	/*
	 * A race condition is prevented between this function and __rtp_recvfrom()
	 * because both functions have to get the instance lock before they can do
	 * anything.  Without holding the instance lock, this function could start
	 * the SSL handshake above in one thread and the __rtp_recvfrom() function
	 * called by the channel thread could read the response and stop the timeout
	 * timer before we have a chance to even start it.
	 */
	dtls_srtp_start_timeout_timer(instance, rtp, rtcp);

	/*
	 * We must call dtls_srtp_check_pending() after starting the timer.
	 * Otherwise we won't prevent the race condition.
	 */
	dtls_srtp_check_pending(instance, rtp, rtcp);
}
#endif

#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
static void dtls_perform_setup(struct dtls_details *dtls)
{
	if (!dtls->ssl || !SSL_is_init_finished(dtls->ssl)) {
		return;
	}

	SSL_clear(dtls->ssl);
	if (dtls->dtls_setup == AST_RTP_DTLS_SETUP_PASSIVE) {
		SSL_set_accept_state(dtls->ssl);
	} else {
		SSL_set_connect_state(dtls->ssl);
	}
	dtls->connection = AST_RTP_DTLS_CONNECTION_NEW;
}
#endif

#ifdef HAVE_PJPROJECT
static void rtp_learning_start(struct ast_rtp *rtp);

/* PJPROJECT ICE callback */
static void ast_rtp_on_ice_complete(pj_ice_sess *ice, pj_status_t status)
{
	struct ast_rtp_instance *instance = ice->user_data;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	ao2_lock(instance);
	if (status == PJ_SUCCESS) {
		struct ast_sockaddr remote_address;

		ast_sockaddr_setnull(&remote_address);
		update_address_with_ice_candidate(ice, AST_RTP_ICE_COMPONENT_RTP, &remote_address);
		if (!ast_sockaddr_isnull(&remote_address)) {
			/* Symmetric RTP must be disabled for the remote address to not get overwritten */
			ast_rtp_instance_set_prop(instance, AST_RTP_PROPERTY_NAT, 0);

			ast_rtp_instance_set_remote_address(instance, &remote_address);
		}

		if (rtp->rtcp) {
			update_address_with_ice_candidate(ice, AST_RTP_ICE_COMPONENT_RTCP, &rtp->rtcp->them);
		}
	}

#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)

	dtls_perform_setup(&rtp->dtls);
	dtls_perform_handshake(instance, &rtp->dtls, 0);

	if (rtp->rtcp && rtp->rtcp->type == AST_RTP_INSTANCE_RTCP_STANDARD) {
		dtls_perform_setup(&rtp->rtcp->dtls);
		dtls_perform_handshake(instance, &rtp->rtcp->dtls, 1);
	}
#endif

	if (!strictrtp) {
		ao2_unlock(instance);
		return;
	}

	ast_verb(4, "%p -- Strict RTP learning after ICE completion\n", rtp);
	rtp_learning_start(rtp);
	ao2_unlock(instance);
}

/* PJPROJECT ICE callback */
static void ast_rtp_on_ice_rx_data(pj_ice_sess *ice, unsigned comp_id, unsigned transport_id, void *pkt, pj_size_t size, const pj_sockaddr_t *src_addr, unsigned src_addr_len)
{
	struct ast_rtp_instance *instance = ice->user_data;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	/* Instead of handling the packet here (which really doesn't work with our architecture) we set a bit to indicate that it should be handled after pj_ice_sess_on_rx_pkt
	 * returns */
	if (transport_id == TRANSPORT_SOCKET_RTP || transport_id == TRANSPORT_SOCKET_RTCP) {
		rtp->passthrough = 1;
	} else if (transport_id == TRANSPORT_TURN_RTP) {
		rtp->rtp_passthrough = 1;
	} else if (transport_id == TRANSPORT_TURN_RTCP) {
		rtp->rtcp_passthrough = 1;
	}
}

/* PJPROJECT ICE callback */
static pj_status_t ast_rtp_on_ice_tx_pkt(pj_ice_sess *ice, unsigned comp_id, unsigned transport_id, const void *pkt, pj_size_t size, const pj_sockaddr_t *dst_addr, unsigned dst_addr_len)
{
	struct ast_rtp_instance *instance = ice->user_data;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	pj_status_t status = PJ_EINVALIDOP;
	pj_ssize_t _size = (pj_ssize_t)size;

	if (transport_id == TRANSPORT_SOCKET_RTP) {
		/* Traffic is destined to go right out the RTP socket we already have */
		status = pj_sock_sendto(rtp->s, pkt, &_size, 0, dst_addr, dst_addr_len);
		/* sendto on a connectionless socket should send all the data, or none at all */
		ast_assert(_size == size || status != PJ_SUCCESS);
	} else if (transport_id == TRANSPORT_SOCKET_RTCP) {
		/* Traffic is destined to go right out the RTCP socket we already have */
		if (rtp->rtcp) {
			status = pj_sock_sendto(rtp->rtcp->s, pkt, &_size, 0, dst_addr, dst_addr_len);
			/* sendto on a connectionless socket should send all the data, or none at all */
			ast_assert(_size == size || status != PJ_SUCCESS);
		} else {
			status = PJ_SUCCESS;
		}
	} else if (transport_id == TRANSPORT_TURN_RTP) {
		/* Traffic is going through the RTP TURN relay */
		if (rtp->turn_rtp) {
			status = pj_turn_sock_sendto(rtp->turn_rtp, pkt, size, dst_addr, dst_addr_len);
		}
	} else if (transport_id == TRANSPORT_TURN_RTCP) {
		/* Traffic is going through the RTCP TURN relay */
		if (rtp->turn_rtcp) {
			status = pj_turn_sock_sendto(rtp->turn_rtcp, pkt, size, dst_addr, dst_addr_len);
		}
	}

	return status;
}

/* ICE Session interface declaration */
static pj_ice_sess_cb ast_rtp_ice_sess_cb = {
	.on_ice_complete = ast_rtp_on_ice_complete,
	.on_rx_data = ast_rtp_on_ice_rx_data,
	.on_tx_pkt = ast_rtp_on_ice_tx_pkt,
};

/*! \brief Worker thread for timerheap */
static int timer_worker_thread(void *data)
{
	pj_ioqueue_t *ioqueue;

	if (pj_ioqueue_create(pool, 1, &ioqueue) != PJ_SUCCESS) {
		return -1;
	}

	while (!timer_terminate) {
		const pj_time_val delay = {0, 10};

		pj_timer_heap_poll(timer_heap, NULL);
		pj_ioqueue_poll(ioqueue, &delay);
	}

	return 0;
}
#endif

static inline int rtp_debug_test_addr(struct ast_sockaddr *addr)
{
	if (!rtpdebug) {
		return 0;
	}
	if (!ast_sockaddr_isnull(&rtpdebugaddr)) {
		if (rtpdebugport) {
			return (ast_sockaddr_cmp(&rtpdebugaddr, addr) == 0); /* look for RTP packets from IP+Port */
		} else {
			return (ast_sockaddr_cmp_addr(&rtpdebugaddr, addr) == 0); /* only look for RTP packets from IP */
		}
	}

	return 1;
}

static inline int rtcp_debug_test_addr(struct ast_sockaddr *addr)
{
	if (!rtcpdebug) {
		return 0;
	}
	if (!ast_sockaddr_isnull(&rtcpdebugaddr)) {
		if (rtcpdebugport) {
			return (ast_sockaddr_cmp(&rtcpdebugaddr, addr) == 0); /* look for RTCP packets from IP+Port */
		} else {
			return (ast_sockaddr_cmp_addr(&rtcpdebugaddr, addr) == 0); /* only look for RTCP packets from IP */
		}
	}

	return 1;
}

#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
/*! \pre instance is locked */
static int dtls_srtp_handle_timeout(struct ast_rtp_instance *instance, int rtcp)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct dtls_details *dtls = !rtcp ? &rtp->dtls : &rtp->rtcp->dtls;
	struct timeval dtls_timeout;

	DTLSv1_handle_timeout(dtls->ssl);
	dtls_srtp_check_pending(instance, rtp, rtcp);

	/* If a timeout can't be retrieved then this recurring scheduled item must stop */
	if (!DTLSv1_get_timeout(dtls->ssl, &dtls_timeout)) {
		dtls->timeout_timer = -1;
		return 0;
	}

	return dtls_timeout.tv_sec * 1000 + dtls_timeout.tv_usec / 1000;
}

/* Scheduler callback */
static int dtls_srtp_handle_rtp_timeout(const void *data)
{
	struct ast_rtp_instance *instance = (struct ast_rtp_instance *)data;
	int reschedule;

	ao2_lock(instance);
	reschedule = dtls_srtp_handle_timeout(instance, 0);
	ao2_unlock(instance);
	if (!reschedule) {
		ao2_ref(instance, -1);
	}

	return reschedule;
}

/* Scheduler callback */
static int dtls_srtp_handle_rtcp_timeout(const void *data)
{
	struct ast_rtp_instance *instance = (struct ast_rtp_instance *)data;
	int reschedule;

	ao2_lock(instance);
	reschedule = dtls_srtp_handle_timeout(instance, 1);
	ao2_unlock(instance);
	if (!reschedule) {
		ao2_ref(instance, -1);
	}

	return reschedule;
}

static void dtls_srtp_start_timeout_timer(struct ast_rtp_instance *instance, struct ast_rtp *rtp, int rtcp)
{
	struct dtls_details *dtls = !rtcp ? &rtp->dtls : &rtp->rtcp->dtls;
	struct timeval dtls_timeout;

	if (DTLSv1_get_timeout(dtls->ssl, &dtls_timeout)) {
		int timeout = dtls_timeout.tv_sec * 1000 + dtls_timeout.tv_usec / 1000;

		ast_assert(dtls->timeout_timer == -1);

		ao2_ref(instance, +1);
		if ((dtls->timeout_timer = ast_sched_add(rtp->sched, timeout,
			!rtcp ? dtls_srtp_handle_rtp_timeout : dtls_srtp_handle_rtcp_timeout, instance)) < 0) {
			ao2_ref(instance, -1);
			ast_log(LOG_WARNING, "Scheduling '%s' DTLS retransmission for RTP instance [%p] failed.\n",
				!rtcp ? "RTP" : "RTCP", instance);
		}
	}
}

/*! \pre Must not be called with the instance locked. */
static void dtls_srtp_stop_timeout_timer(struct ast_rtp_instance *instance, struct ast_rtp *rtp, int rtcp)
{
	struct dtls_details *dtls = !rtcp ? &rtp->dtls : &rtp->rtcp->dtls;

	AST_SCHED_DEL_UNREF(rtp->sched, dtls->timeout_timer, ao2_ref(instance, -1));
}

/*! \pre instance is locked */
static void dtls_srtp_check_pending(struct ast_rtp_instance *instance, struct ast_rtp *rtp, int rtcp)
{
	struct dtls_details *dtls = !rtcp ? &rtp->dtls : &rtp->rtcp->dtls;
	size_t pending;

	if (!dtls->ssl || !dtls->write_bio) {
		return;
	}

	pending = BIO_ctrl_pending(dtls->write_bio);

	if (pending > 0) {
		char outgoing[pending];
		size_t out;
		struct ast_sockaddr remote_address = { {0, } };
		int ice;

		if (!rtcp) {
			ast_rtp_instance_get_remote_address(instance, &remote_address);
		} else {
			ast_sockaddr_copy(&remote_address, &rtp->rtcp->them);
		}

		/* If we do not yet know an address to send this to defer it until we do */
		if (ast_sockaddr_isnull(&remote_address)) {
			return;
		}

		out = BIO_read(dtls->write_bio, outgoing, sizeof(outgoing));
		__rtp_sendto(instance, outgoing, out, 0, &remote_address, rtcp, &ice, 0);
	}
}

/* Scheduler callback */
static int dtls_srtp_renegotiate(const void *data)
{
	struct ast_rtp_instance *instance = (struct ast_rtp_instance *)data;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	ao2_lock(instance);

	SSL_renegotiate(rtp->dtls.ssl);
	SSL_do_handshake(rtp->dtls.ssl);
	dtls_srtp_check_pending(instance, rtp, 0);

	if (rtp->rtcp && rtp->rtcp->dtls.ssl && rtp->rtcp->dtls.ssl != rtp->dtls.ssl) {
		SSL_renegotiate(rtp->rtcp->dtls.ssl);
		SSL_do_handshake(rtp->rtcp->dtls.ssl);
		dtls_srtp_check_pending(instance, rtp, 1);
	}

	rtp->rekeyid = -1;

	ao2_unlock(instance);
	ao2_ref(instance, -1);

	return 0;
}

static int dtls_srtp_add_local_ssrc(struct ast_rtp *rtp, struct ast_rtp_instance *instance, int rtcp, unsigned int ssrc, int set_remote_policy)
{
	unsigned char material[SRTP_MASTER_LEN * 2];
	unsigned char *local_key, *local_salt, *remote_key, *remote_salt;
	struct ast_srtp_policy *local_policy, *remote_policy = NULL;
	int res = -1;
	struct dtls_details *dtls = !rtcp ? &rtp->dtls : &rtp->rtcp->dtls;

	/* Produce key information and set up SRTP */
	if (!SSL_export_keying_material(dtls->ssl, material, SRTP_MASTER_LEN * 2, "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0)) {
		ast_log(LOG_WARNING, "Unable to extract SRTP keying material from DTLS-SRTP negotiation on RTP instance '%p'\n",
			instance);
		return -1;
	}

	/* Whether we are acting as a server or client determines where the keys/salts are */
	if (rtp->dtls.dtls_setup == AST_RTP_DTLS_SETUP_ACTIVE) {
		local_key = material;
		remote_key = local_key + SRTP_MASTER_KEY_LEN;
		local_salt = remote_key + SRTP_MASTER_KEY_LEN;
		remote_salt = local_salt + SRTP_MASTER_SALT_LEN;
	} else {
		remote_key = material;
		local_key = remote_key + SRTP_MASTER_KEY_LEN;
		remote_salt = local_key + SRTP_MASTER_KEY_LEN;
		local_salt = remote_salt + SRTP_MASTER_SALT_LEN;
	}

	if (!(local_policy = res_srtp_policy->alloc())) {
		return -1;
	}

	if (res_srtp_policy->set_master_key(local_policy, local_key, SRTP_MASTER_KEY_LEN, local_salt, SRTP_MASTER_SALT_LEN) < 0) {
		ast_log(LOG_WARNING, "Could not set key/salt information on local policy of '%p' when setting up DTLS-SRTP\n", rtp);
		goto error;
	}

	if (res_srtp_policy->set_suite(local_policy, rtp->suite)) {
		ast_log(LOG_WARNING, "Could not set suite to '%u' on local policy of '%p' when setting up DTLS-SRTP\n", rtp->suite, rtp);
		goto error;
	}

	res_srtp_policy->set_ssrc(local_policy, ssrc, 0);

	if (set_remote_policy) {
		if (!(remote_policy = res_srtp_policy->alloc())) {
			goto error;
		}

		if (res_srtp_policy->set_master_key(remote_policy, remote_key, SRTP_MASTER_KEY_LEN, remote_salt, SRTP_MASTER_SALT_LEN) < 0) {
			ast_log(LOG_WARNING, "Could not set key/salt information on remote policy of '%p' when setting up DTLS-SRTP\n", rtp);
			goto error;
		}

		if (res_srtp_policy->set_suite(remote_policy, rtp->suite)) {
			ast_log(LOG_WARNING, "Could not set suite to '%u' on remote policy of '%p' when setting up DTLS-SRTP\n", rtp->suite, rtp);
			goto error;
		}

		res_srtp_policy->set_ssrc(remote_policy, 0, 1);
	}

	if (ast_rtp_instance_add_srtp_policy(instance, remote_policy, local_policy, rtcp)) {
		ast_log(LOG_WARNING, "Could not set policies when setting up DTLS-SRTP on '%p'\n", rtp);
		goto error;
	}

	res = 0;

error:
	/* policy->destroy() called even on success to release local reference to these resources */
	res_srtp_policy->destroy(local_policy);

	if (remote_policy) {
		res_srtp_policy->destroy(remote_policy);
	}

	return res;
}

static int dtls_srtp_setup(struct ast_rtp *rtp, struct ast_rtp_instance *instance, int rtcp)
{
	struct dtls_details *dtls = !rtcp ? &rtp->dtls : &rtp->rtcp->dtls;
	int index;

	/* If a fingerprint is present in the SDP make sure that the peer certificate matches it */
	if (rtp->dtls_verify & AST_RTP_DTLS_VERIFY_FINGERPRINT) {
		X509 *certificate;

		if (!(certificate = SSL_get_peer_certificate(dtls->ssl))) {
			ast_log(LOG_WARNING, "No certificate was provided by the peer on RTP instance '%p'\n", instance);
			return -1;
		}

		/* If a fingerprint is present in the SDP make sure that the peer certificate matches it */
		if (rtp->remote_fingerprint[0]) {
			const EVP_MD *type;
			unsigned char fingerprint[EVP_MAX_MD_SIZE];
			unsigned int size;

			if (rtp->remote_hash == AST_RTP_DTLS_HASH_SHA1) {
				type = EVP_sha1();
			} else if (rtp->remote_hash == AST_RTP_DTLS_HASH_SHA256) {
				type = EVP_sha256();
			} else {
				ast_log(LOG_WARNING, "Unsupported fingerprint hash type on RTP instance '%p'\n", instance);
				return -1;
			}

			if (!X509_digest(certificate, type, fingerprint, &size) ||
			    !size ||
			    memcmp(fingerprint, rtp->remote_fingerprint, size)) {
				X509_free(certificate);
				ast_log(LOG_WARNING, "Fingerprint provided by remote party does not match that of peer certificate on RTP instance '%p'\n",
					instance);
				return -1;
			}
		}

		X509_free(certificate);
	}

	if (dtls_srtp_add_local_ssrc(rtp, instance, rtcp, ast_rtp_instance_get_ssrc(instance), 1)) {
		return -1;
	}

	for (index = 0; index < AST_VECTOR_SIZE(&rtp->ssrc_mapping); ++index) {
		struct rtp_ssrc_mapping *mapping = AST_VECTOR_GET_ADDR(&rtp->ssrc_mapping, index);

		if (dtls_srtp_add_local_ssrc(rtp, instance, rtcp, ast_rtp_instance_get_ssrc(mapping->instance), 0)) {
			return -1;
		}
	}

	if (rtp->rekey) {
		ao2_ref(instance, +1);
		if ((rtp->rekeyid = ast_sched_add(rtp->sched, rtp->rekey * 1000, dtls_srtp_renegotiate, instance)) < 0) {
			ao2_ref(instance, -1);
			return -1;
		}
	}

	return 0;
}
#endif

/*! \brief Helper function to compare an elem in a vector by value */
static int compare_by_value(int elem, int value)
{
	return elem - value;
}

/*! \brief Helper function to find an elem in a vector by value */
static int find_by_value(int elem, int value)
{
	return elem == value;
}

static int rtcp_mux(struct ast_rtp *rtp, const unsigned char *packet)
{
	uint8_t version;
	uint8_t pt;
	uint8_t m;

	if (!rtp->rtcp || rtp->rtcp->type != AST_RTP_INSTANCE_RTCP_MUX) {
		return 0;
	}

	version = (packet[0] & 0XC0) >> 6;
	if (version == 0) {
		/* version 0 indicates this is a STUN packet and shouldn't
		 * be interpreted as a possible RTCP packet
		 */
		return 0;
	}

	/* The second octet of a packet will be one of the following:
	 * For RTP: The marker bit (1 bit) and the RTP payload type (7 bits)
	 * For RTCP: The payload type (8)
	 *
	 * RTP has a forbidden range of payload types (64-95) since these
	 * will conflict with RTCP payload numbers if the marker bit is set.
	 */
	m = packet[1] & 0x80;
	pt = packet[1] & 0x7F;
	if (m && pt >= 64 && pt <= 95) {
		return 1;
	}
	return 0;
}

/*! \pre instance is locked */
static int __rtp_recvfrom(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa, int rtcp)
{
	int len;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
	char *in = buf;
#endif
#ifdef HAVE_PJPROJECT
	struct ast_sockaddr *loop = rtcp ? &rtp->rtcp_loop : &rtp->rtp_loop;
#endif

	if ((len = ast_recvfrom(rtcp ? rtp->rtcp->s : rtp->s, buf, size, flags, sa)) < 0) {
	   return len;
	}

#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
	/* If this is an SSL packet pass it to OpenSSL for processing. RFC section for first byte value:
	 * https://tools.ietf.org/html/rfc5764#section-5.1.2 */
	if ((*in >= 20) && (*in <= 63)) {
		struct dtls_details *dtls = !rtcp ? &rtp->dtls : &rtp->rtcp->dtls;
		int res = 0;

		/* If no SSL session actually exists terminate things */
		if (!dtls->ssl) {
			ast_log(LOG_ERROR, "Received SSL traffic on RTP instance '%p' without an SSL session\n",
				instance);
			return -1;
		}

		/*
		 * A race condition is prevented between dtls_perform_handshake()
		 * and this function because both functions have to get the
		 * instance lock before they can do anything.  The
		 * dtls_perform_handshake() function needs to start the timer
		 * before we stop it below.
		 */

		/* Before we feed data into OpenSSL ensure that the timeout timer is either stopped or completed */
		ao2_unlock(instance);
		dtls_srtp_stop_timeout_timer(instance, rtp, rtcp);
		ao2_lock(instance);

		/* If we don't yet know if we are active or passive and we receive a packet... we are obviously passive */
		if (dtls->dtls_setup == AST_RTP_DTLS_SETUP_ACTPASS) {
			dtls->dtls_setup = AST_RTP_DTLS_SETUP_PASSIVE;
			SSL_set_accept_state(dtls->ssl);
		}

		dtls_srtp_check_pending(instance, rtp, rtcp);

		BIO_write(dtls->read_bio, buf, len);

		len = SSL_read(dtls->ssl, buf, len);

		if ((len < 0) && (SSL_get_error(dtls->ssl, len) == SSL_ERROR_SSL)) {
			unsigned long error = ERR_get_error();
			ast_log(LOG_ERROR, "DTLS failure occurred on RTP instance '%p' due to reason '%s', terminating\n",
				instance, ERR_reason_error_string(error));
			return -1;
		}

		dtls_srtp_check_pending(instance, rtp, rtcp);

		if (SSL_is_init_finished(dtls->ssl)) {
			/* Any further connections will be existing since this is now established */
			dtls->connection = AST_RTP_DTLS_CONNECTION_EXISTING;
			/* Use the keying material to set up key/salt information */
			if ((res = dtls_srtp_setup(rtp, instance, rtcp))) {
				return res;
			}
			/* Notify that dtls has been established */
			res = RTP_DTLS_ESTABLISHED;
		} else {
			/* Since we've sent additional traffic start the timeout timer for retransmission */
			dtls_srtp_start_timeout_timer(instance, rtp, rtcp);
		}

		return res;
	}
#endif

#ifdef HAVE_PJPROJECT
	if (!ast_sockaddr_isnull(loop) && !ast_sockaddr_cmp(loop, sa)) {
		/* ICE traffic will have been handled in the TURN callback, so skip it but update the address
		 * so it reflects the actual source and not the loopback
		 */
		if (rtcp) {
			ast_sockaddr_copy(sa, &rtp->rtcp->them);
		} else {
			ast_rtp_instance_get_remote_address(instance, sa);
		}
	} else if (rtp->ice) {
		pj_str_t combined = pj_str(ast_sockaddr_stringify(sa));
		pj_sockaddr address;
		pj_status_t status;
		struct ice_wrap *ice;

		pj_thread_register_check();

		pj_sockaddr_parse(pj_AF_UNSPEC(), 0, &combined, &address);

		/* Release the instance lock to avoid deadlock with PJPROJECT group lock */
		ice = rtp->ice;
		ao2_ref(ice, +1);
		ao2_unlock(instance);
		status = pj_ice_sess_on_rx_pkt(ice->real_ice,
			rtcp ? AST_RTP_ICE_COMPONENT_RTCP : AST_RTP_ICE_COMPONENT_RTP,
			rtcp ? TRANSPORT_SOCKET_RTCP : TRANSPORT_SOCKET_RTP, buf, len, &address,
			pj_sockaddr_get_len(&address));
		ao2_ref(ice, -1);
		ao2_lock(instance);
		if (status != PJ_SUCCESS) {
			char buf[100];

			pj_strerror(status, buf, sizeof(buf));
			ast_log(LOG_WARNING, "PJ ICE Rx error status code: %d '%s'.\n",
				(int)status, buf);
			return -1;
		}
		if (!rtp->passthrough) {
			/* If a unidirectional ICE negotiation occurs then lock on to the source of the
			 * ICE traffic and use it as the target. This will occur if the remote side only
			 * wants to receive media but never send to us.
			 */
			if (!rtp->ice_active_remote_candidates && !rtp->ice_proposed_remote_candidates) {
				if (rtcp) {
					ast_sockaddr_copy(&rtp->rtcp->them, sa);
				} else {
					ast_rtp_instance_set_remote_address(instance, sa);
				}
			}
			return 0;
		}
		rtp->passthrough = 0;
	}
#endif

	return len;
}

/*! \pre instance is locked */
static int rtcp_recvfrom(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa)
{
	return __rtp_recvfrom(instance, buf, size, flags, sa, 1);
}

/*! \pre instance is locked */
static int rtp_recvfrom(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa)
{
	return __rtp_recvfrom(instance, buf, size, flags, sa, 0);
}

/*! \pre instance is locked */
static int __rtp_sendto(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa, int rtcp, int *via_ice, int use_srtp)
{
	int len = size;
	void *temp = buf;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_rtp_instance *transport = rtp->bundled ? rtp->bundled : instance;
	struct ast_rtp *transport_rtp = ast_rtp_instance_get_data(transport);
	struct ast_srtp *srtp = ast_rtp_instance_get_srtp(transport, rtcp);
	int res;

	*via_ice = 0;

	if (use_srtp && res_srtp && srtp && res_srtp->protect(srtp, &temp, &len, rtcp) < 0) {
		return -1;
	}

#ifdef HAVE_PJPROJECT
	if (transport_rtp->ice) {
		enum ast_rtp_ice_component_type component = rtcp ? AST_RTP_ICE_COMPONENT_RTCP : AST_RTP_ICE_COMPONENT_RTP;
		pj_status_t status;
		struct ice_wrap *ice;

		/* If RTCP is sharing the same socket then use the same component */
		if (rtcp && rtp->rtcp->s == rtp->s) {
			component = AST_RTP_ICE_COMPONENT_RTP;
		}

		pj_thread_register_check();

		/* Release the instance lock to avoid deadlock with PJPROJECT group lock */
		ice = transport_rtp->ice;
		ao2_ref(ice, +1);
		if (instance == transport) {
			ao2_unlock(instance);
		}
		status = pj_ice_sess_send_data(ice->real_ice, component, temp, len);
		ao2_ref(ice, -1);
		if (instance == transport) {
			ao2_lock(instance);
		}
		if (status == PJ_SUCCESS) {
			*via_ice = 1;
			return len;
		}
	}
#endif

	res = ast_sendto(rtcp ? transport_rtp->rtcp->s : transport_rtp->s, temp, len, flags, sa);
	if (res > 0) {
		ast_rtp_instance_set_last_tx(instance, time(NULL));
	}

	return res;
}

/*! \pre instance is locked */
static int rtcp_sendto(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa, int *ice)
{
	return __rtp_sendto(instance, buf, size, flags, sa, 1, ice, 1);
}

/*! \pre instance is locked */
static int rtp_sendto(struct ast_rtp_instance *instance, void *buf, size_t size, int flags, struct ast_sockaddr *sa, int *ice)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int hdrlen = 12;
	int res;

	if ((res = __rtp_sendto(instance, buf, size, flags, sa, 0, ice, 1)) > 0) {
		rtp->txcount++;
		rtp->txoctetcount += (res - hdrlen);
	}

	return res;
}

static int rtp_get_rate(struct ast_format *format)
{
	/* For those wondering: due to a fluke in RFC publication, G.722 is advertised
	 * as having a sample rate of 8kHz, while implementations must know that its
	 * real rate is 16kHz. Seriously.
	 */
	return (ast_format_cmp(format, ast_format_g722) == AST_FORMAT_CMP_EQUAL) ? 8000 : (int)ast_format_get_sample_rate(format);
}

static unsigned int ast_rtcp_calc_interval(struct ast_rtp *rtp)
{
	unsigned int interval;
	/*! \todo XXX Do a more reasonable calculation on this one
	 * Look in RFC 3550 Section A.7 for an example*/
	interval = rtcpinterval;
	return interval;
}

/*! \brief Calculate normal deviation */
static double normdev_compute(double normdev, double sample, unsigned int sample_count)
{
	normdev = normdev * sample_count + sample;
	sample_count++;

	/*
	 It's possible the sample_count hits the maximum value and back to 0.
	 Set to 1 to prevent the divide by zero crash if the sample_count is 0.
	 */
	if (sample_count == 0) {
		sample_count = 1;
	}

	return normdev / sample_count;
}

static double stddev_compute(double stddev, double sample, double normdev, double normdev_curent, unsigned int sample_count)
{
/*
		for the formula check http://www.cs.umd.edu/~austinjp/constSD.pdf
		return sqrt( (sample_count*pow(stddev,2) + sample_count*pow((sample-normdev)/(sample_count+1),2) + pow(sample-normdev_curent,2)) / (sample_count+1));
		we can compute the sigma^2 and that way we would have to do the sqrt only 1 time at the end and would save another pow 2 compute
		optimized formula
*/
#define SQUARE(x) ((x) * (x))

	stddev = sample_count * stddev;
	sample_count++;

	/*
	 It's possible the sample_count hits the maximum value and back to 0.
	 Set to 1 to prevent the divide by zero crash if the sample_count is 0.
	 */
	if (sample_count == 0) {
		sample_count = 1;
	}

	return stddev +
		( sample_count * SQUARE( (sample - normdev) / sample_count ) ) +
		( SQUARE(sample - normdev_curent) / sample_count );

#undef SQUARE
}

static int create_new_socket(const char *type, int af)
{
	int sock = ast_socket_nonblock(af, SOCK_DGRAM, 0);

	if (sock < 0) {
		ast_log(LOG_WARNING, "Unable to allocate %s socket: %s\n", type, strerror(errno));
		return sock;
	}

#ifdef SO_NO_CHECK
	if (nochecksums) {
		setsockopt(sock, SOL_SOCKET, SO_NO_CHECK, &nochecksums, sizeof(nochecksums));
	}
#endif

	return sock;
}

/*!
 * \internal
 * \brief Initializes sequence values and probation for learning mode.
 * \note This is an adaptation of pjmedia's pjmedia_rtp_seq_init function.
 *
 * \param info The learning information to track
 * \param seq sequence number read from the rtp header to initialize the information with
 */
static void rtp_learning_seq_init(struct rtp_learning_info *info, uint16_t seq)
{
	info->max_seq = seq;
	info->packets = learning_min_sequential;
	memset(&info->received, 0, sizeof(info->received));
}

/*!
 * \internal
 * \brief Updates sequence information for learning mode and determines if probation/learning mode should remain in effect.
 * \note This function was adapted from pjmedia's pjmedia_rtp_seq_update function.
 *
 * \param info Structure tracking the learning progress of some address
 * \param seq sequence number read from the rtp header
 * \retval 0 if probation mode should exit for this address
 * \retval non-zero if probation mode should continue
 */
static int rtp_learning_rtp_seq_update(struct rtp_learning_info *info, uint16_t seq)
{
	if (seq == (uint16_t) (info->max_seq + 1)) {
		/* packet is in sequence */
		info->packets--;
	} else {
		/* Sequence discontinuity; reset */
		info->packets = learning_min_sequential - 1;
		info->received = ast_tvnow();
	}

	/* Only check time if strictrtp is set to yes. Otherwise, we only needed to check seqno */
	if (strictrtp == STRICT_RTP_YES) {
		switch (info->stream_type) {
		case AST_MEDIA_TYPE_UNKNOWN:
		case AST_MEDIA_TYPE_AUDIO:
			/*
			 * Protect against packet floods by checking that we
			 * received the packet sequence in at least the minimum
			 * allowed time.
			 */
			if (ast_tvzero(info->received)) {
				info->received = ast_tvnow();
			} else if (!info->packets
				&& ast_tvdiff_ms(ast_tvnow(), info->received) < learning_min_duration) {
				/* Packet flood; reset */
				info->packets = learning_min_sequential - 1;
				info->received = ast_tvnow();
			}
			break;
		case AST_MEDIA_TYPE_VIDEO:
		case AST_MEDIA_TYPE_IMAGE:
		case AST_MEDIA_TYPE_TEXT:
		case AST_MEDIA_TYPE_END:
			break;
		}
	}

	info->max_seq = seq;

	return info->packets;
}

/*!
 * \brief Start the strictrtp learning mode.
 *
 * \param rtp RTP session description
 *
 * \return Nothing
 */
static void rtp_learning_start(struct ast_rtp *rtp)
{
	rtp->strict_rtp_state = STRICT_RTP_LEARN;
	memset(&rtp->rtp_source_learn.proposed_address, 0,
		sizeof(rtp->rtp_source_learn.proposed_address));
	rtp->rtp_source_learn.start = ast_tvnow();
	rtp_learning_seq_init(&rtp->rtp_source_learn, (uint16_t) rtp->lastrxseqno);
}

#ifdef HAVE_PJPROJECT
/*!
 * \internal
 * \brief Checks an address against the ICE blacklist
 * \note If there is no ice_blacklist list, always returns 0
 *
 * \param address The address to consider
 * \retval 0 if address is not ICE blacklisted
 * \retval 1 if address is ICE blacklisted
 */
static int rtp_address_is_ice_blacklisted(const pj_sockaddr_t *address)
{
	char buf[PJ_INET6_ADDRSTRLEN];
	struct ast_sockaddr saddr;
	int result = 1;

	ast_sockaddr_parse(&saddr, pj_sockaddr_print(address, buf, sizeof(buf), 0), 0);

	ast_rwlock_rdlock(&ice_blacklist_lock);
	if (!ice_blacklist || (ast_apply_ha(ice_blacklist, &saddr) == AST_SENSE_ALLOW)) {
		result = 0;
	}
	ast_rwlock_unlock(&ice_blacklist_lock);

	return result;
}

/*!
 * \internal
 * \brief Checks an address against the STUN blacklist
 * \since 13.16.0
 *
 * \note If there is no stun_blacklist list, always returns 0
 *
 * \param addr The address to consider
 *
 * \retval 0 if address is not STUN blacklisted
 * \retval 1 if address is STUN blacklisted
 */
static int stun_address_is_blacklisted(const struct ast_sockaddr *addr)
{
	int result = 1;

	ast_rwlock_rdlock(&stun_blacklist_lock);
	if (!stun_blacklist
		|| ast_apply_ha(stun_blacklist, addr) == AST_SENSE_ALLOW) {
		result = 0;
	}
	ast_rwlock_unlock(&stun_blacklist_lock);

	return result;
}

/*! \pre instance is locked */
static void rtp_add_candidates_to_ice(struct ast_rtp_instance *instance, struct ast_rtp *rtp, struct ast_sockaddr *addr, int port, int component,
				      int transport)
{
	pj_sockaddr address[PJ_ICE_MAX_CAND];
	unsigned int count = PJ_ARRAY_SIZE(address), pos = 0;
	unsigned int max_count = PJ_ARRAY_SIZE(address);
	int basepos = -1;

	/* Add all the local interface IP addresses */
	if (ast_sockaddr_is_ipv4(addr)) {
		pj_enum_ip_interface(pj_AF_INET(), &count, address);
	} else if (ast_sockaddr_is_any(addr)) {
		pj_enum_ip_interface(pj_AF_UNSPEC(), &count, address);
	} else {
		pj_enum_ip_interface(pj_AF_INET6(), &count, address);
	}

	count += host_candidate_overrides_apply(count, max_count, address);

	for (pos = 0; pos < count; pos++) {
		if (!rtp_address_is_ice_blacklisted(&address[pos])) {
			if (basepos == -1) {
				basepos = pos;
			}
			pj_sockaddr_set_port(&address[pos], port);
			ast_rtp_ice_add_cand(instance, rtp, component, transport,
				PJ_ICE_CAND_TYPE_HOST, 65535, &address[pos], &address[pos], NULL,
				pj_sockaddr_get_len(&address[pos]));
		}
	}
	if (basepos == -1) {
		/* start with first address unless excluded above */
		basepos = 0;
	}

	/* If configured to use a STUN server to get our external mapped address do so */
	if (count && stunaddr.sin_addr.s_addr && !stun_address_is_blacklisted(addr) &&
		(ast_sockaddr_is_ipv4(addr) || ast_sockaddr_is_any(addr))) {
		struct sockaddr_in answer;
		int rsp;

		/*
		 * The instance should not be locked because we can block
		 * waiting for a STUN respone.
		 */
		ao2_unlock(instance);
		rsp = ast_stun_request(component == AST_RTP_ICE_COMPONENT_RTCP
			? rtp->rtcp->s : rtp->s, &stunaddr, NULL, &answer);
		ao2_lock(instance);
		if (!rsp) {
			pj_sockaddr base;

			/* Use the first local IPv4 host candidate as the base */
			for (pos = basepos; pos < count; pos++) {
				if (address[pos].addr.sa_family == PJ_AF_INET &&
					!rtp_address_is_ice_blacklisted(&address[pos])) {
					pj_sockaddr_cp(&base, &address[pos]);
					break;
				}
			}

			if (pos < count) {
				pj_sockaddr ext;
				pj_str_t mapped = pj_str(ast_strdupa(ast_inet_ntoa(answer.sin_addr)));
				int srflx = 1;

				pj_sockaddr_init(pj_AF_INET(), &ext, &mapped, ntohs(answer.sin_port));

				/*
				 * If the returned address is the same as one of our host
				 * candidates, don't send the srflx
				 */
				for (pos = 0; pos < count; pos++) {
					if (pj_sockaddr_cmp(&address[pos], &ext) == 0 &&
						!rtp_address_is_ice_blacklisted(&address[pos])) {
						srflx = 0;
						break;
					}
				}

				if (srflx) {
					ast_rtp_ice_add_cand(instance, rtp, component, transport,
						PJ_ICE_CAND_TYPE_SRFLX, 65535, &ext, &base, &base,
						pj_sockaddr_get_len(&ext));
				}
			}
		}
	}

	/* If configured to use a TURN relay create a session and allocate */
	if (pj_strlen(&turnaddr)) {
		ast_rtp_ice_turn_request(instance, component, AST_TRANSPORT_TCP, pj_strbuf(&turnaddr), turnport,
			pj_strbuf(&turnusername), pj_strbuf(&turnpassword));
	}
}
#endif

/*!
 * \internal
 * \brief Calculates the elapsed time from issue of the first tx packet in an
 *        rtp session and a specified time
 *
 * \param rtp pointer to the rtp struct with the transmitted rtp packet
 * \param delivery time of delivery - if NULL or zero value, will be ast_tvnow()
 *
 * \return time elapsed in milliseconds
 */
static unsigned int calc_txstamp(struct ast_rtp *rtp, struct timeval *delivery)
{
	struct timeval t;
	long ms;

	if (ast_tvzero(rtp->txcore)) {
		rtp->txcore = ast_tvnow();
		rtp->txcore.tv_usec -= rtp->txcore.tv_usec % 20000;
	}

	t = (delivery && !ast_tvzero(*delivery)) ? *delivery : ast_tvnow();
	if ((ms = ast_tvdiff_ms(t, rtp->txcore)) < 0) {
		ms = 0;
	}
	rtp->txcore = t;

	return (unsigned int) ms;
}

#ifdef HAVE_PJPROJECT
/*!
 * \internal
 * \brief Creates an ICE session. Can be used to replace a destroyed ICE session.
 *
 * \param instance RTP instance for which the ICE session is being replaced
 * \param addr ast_sockaddr to use for adding RTP candidates to the ICE session
 * \param port port to use for adding RTP candidates to the ICE session
 * \param replace 0 when creating a new session, 1 when replacing a destroyed session
 *
 * \pre instance is locked
 *
 * \retval 0 on success
 * \retval -1 on failure
 */
static int ice_create(struct ast_rtp_instance *instance, struct ast_sockaddr *addr,
	int port, int replace)
{
	pj_stun_config stun_config;
	pj_str_t ufrag, passwd;
	pj_status_t status;
	struct ice_wrap *ice_old;
	struct ice_wrap *ice;
	pj_ice_sess *real_ice = NULL;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	ao2_cleanup(rtp->ice_local_candidates);
	rtp->ice_local_candidates = NULL;

	ice = ao2_alloc_options(sizeof(*ice), ice_wrap_dtor, AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!ice) {
		ast_rtp_ice_stop(instance);
		return -1;
	}

	pj_thread_register_check();

	pj_stun_config_init(&stun_config, &cachingpool.factory, 0, NULL, timer_heap);

	ufrag = pj_str(rtp->local_ufrag);
	passwd = pj_str(rtp->local_passwd);

	/* Release the instance lock to avoid deadlock with PJPROJECT group lock */
	ao2_unlock(instance);
	/* Create an ICE session for ICE negotiation */
	status = pj_ice_sess_create(&stun_config, NULL, PJ_ICE_SESS_ROLE_UNKNOWN,
		rtp->ice_num_components, &ast_rtp_ice_sess_cb, &ufrag, &passwd, NULL, &real_ice);
	ao2_lock(instance);
	if (status == PJ_SUCCESS) {
		/* Safely complete linking the ICE session into the instance */
		real_ice->user_data = instance;
		ice->real_ice = real_ice;
		ice_old = rtp->ice;
		rtp->ice = ice;
		if (ice_old) {
			ao2_unlock(instance);
			ao2_ref(ice_old, -1);
			ao2_lock(instance);
		}

		/* Add all of the available candidates to the ICE session */
		rtp_add_candidates_to_ice(instance, rtp, addr, port, AST_RTP_ICE_COMPONENT_RTP,
			TRANSPORT_SOCKET_RTP);

		/* Only add the RTCP candidates to ICE when replacing the session and if
		 * the ICE session contains more than just an RTP component. New sessions
		 * handle this in a separate part of the setup phase */
		if (replace && rtp->rtcp && rtp->ice_num_components > 1) {
			rtp_add_candidates_to_ice(instance, rtp, &rtp->rtcp->us,
				ast_sockaddr_port(&rtp->rtcp->us), AST_RTP_ICE_COMPONENT_RTCP,
				TRANSPORT_SOCKET_RTCP);
		}

		return 0;
	}

	/*
	 * It is safe to unref this while instance is locked here.
	 * It was not initialized with a real_ice pointer.
	 */
	ao2_ref(ice, -1);

	ast_rtp_ice_stop(instance);
	return -1;

}
#endif

static int rtp_allocate_transport(struct ast_rtp_instance *instance, struct ast_rtp *rtp)
{
	int x, startplace;

	rtp->strict_rtp_state = (strictrtp ? STRICT_RTP_CLOSED : STRICT_RTP_OPEN);

	/* Create a new socket for us to listen on and use */
	if ((rtp->s =
	     create_new_socket("RTP",
			       ast_sockaddr_is_ipv4(&rtp->bind_address) ? AF_INET  :
			       ast_sockaddr_is_ipv6(&rtp->bind_address) ? AF_INET6 : -1)) < 0) {
		ast_log(LOG_WARNING, "Failed to create a new socket for RTP instance '%p'\n", instance);
		return -1;
	}

	/* Now actually find a free RTP port to use */
	x = (rtpend == rtpstart) ? rtpstart : (ast_random() % (rtpend - rtpstart)) + rtpstart;
	x = x & ~1;
	startplace = x;

	for (;;) {
		ast_sockaddr_set_port(&rtp->bind_address, x);
		/* Try to bind, this will tell us whether the port is available or not */
		if (!ast_bind(rtp->s, &rtp->bind_address)) {
			ast_debug(1, "Allocated port %d for RTP instance '%p'\n", x, instance);
			ast_rtp_instance_set_local_address(instance, &rtp->bind_address);
			ast_test_suite_event_notify("RTP_PORT_ALLOCATED", "Port: %d", x);
			break;
		}

		x += 2;
		if (x > rtpend) {
			x = (rtpstart + 1) & ~1;
		}

		/* See if we ran out of ports or if the bind actually failed because of something other than the address being in use */
		if (x == startplace || (errno != EADDRINUSE && errno != EACCES)) {
			ast_log(LOG_ERROR, "Oh dear... we couldn't allocate a port for RTP instance '%p'\n", instance);
			close(rtp->s);
			rtp->s = -1;
			return -1;
		}
	}

#ifdef HAVE_PJPROJECT
	/* Initialize synchronization aspects */
	ast_cond_init(&rtp->cond, NULL);

	generate_random_string(rtp->local_ufrag, sizeof(rtp->local_ufrag));
	generate_random_string(rtp->local_passwd, sizeof(rtp->local_passwd));

	/* Create an ICE session for ICE negotiation */
	if (icesupport) {
		rtp->ice_num_components = 2;
		ast_debug(3, "Creating ICE session %s (%d) for RTP instance '%p'\n", ast_sockaddr_stringify(&rtp->bind_address), x, instance);
		if (ice_create(instance, &rtp->bind_address, x, 0)) {
			ast_log(LOG_NOTICE, "Failed to create ICE session\n");
		} else {
			rtp->ice_port = x;
			ast_sockaddr_copy(&rtp->ice_original_rtp_addr, &rtp->bind_address);
		}
	}
#endif

#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
	rtp->rekeyid = -1;
	rtp->dtls.timeout_timer = -1;
#endif

	return 0;
}

static void rtp_deallocate_transport(struct ast_rtp_instance *instance, struct ast_rtp *rtp)
{
	int saved_rtp_s = rtp->s;
#ifdef HAVE_PJPROJECT
	struct timeval wait = ast_tvadd(ast_tvnow(), ast_samp2tv(TURN_STATE_WAIT_TIME, 1000));
	struct timespec ts = { .tv_sec = wait.tv_sec, .tv_nsec = wait.tv_usec * 1000, };
#endif

#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
	ast_rtp_dtls_stop(instance);
#endif

	/* Close our own socket so we no longer get packets */
	if (rtp->s > -1) {
		close(rtp->s);
		rtp->s = -1;
	}

	/* Destroy RTCP if it was being used */
	if (rtp->rtcp && rtp->rtcp->s > -1) {
		if (saved_rtp_s != rtp->rtcp->s) {
			close(rtp->rtcp->s);
		}
		rtp->rtcp->s = -1;
	}

#ifdef HAVE_PJPROJECT
	pj_thread_register_check();

	/*
	 * The instance lock is already held.
	 *
	 * Destroy the RTP TURN relay if being used
	 */
	if (rtp->turn_rtp) {
		rtp->turn_state = PJ_TURN_STATE_NULL;

		/* Release the instance lock to avoid deadlock with PJPROJECT group lock */
		ao2_unlock(instance);
		pj_turn_sock_destroy(rtp->turn_rtp);
		ao2_lock(instance);
		while (rtp->turn_state != PJ_TURN_STATE_DESTROYING) {
			ast_cond_timedwait(&rtp->cond, ao2_object_get_lockaddr(instance), &ts);
		}
		rtp->turn_rtp = NULL;
	}

	/* Destroy the RTCP TURN relay if being used */
	if (rtp->turn_rtcp) {
		rtp->turn_state = PJ_TURN_STATE_NULL;

		/* Release the instance lock to avoid deadlock with PJPROJECT group lock */
		ao2_unlock(instance);
		pj_turn_sock_destroy(rtp->turn_rtcp);
		ao2_lock(instance);
		while (rtp->turn_state != PJ_TURN_STATE_DESTROYING) {
			ast_cond_timedwait(&rtp->cond, ao2_object_get_lockaddr(instance), &ts);
		}
		rtp->turn_rtcp = NULL;
	}

	/* Destroy any ICE session */
	ast_rtp_ice_stop(instance);

	/* Destroy any candidates */
	if (rtp->ice_local_candidates) {
		ao2_ref(rtp->ice_local_candidates, -1);
		rtp->ice_local_candidates = NULL;
	}

	if (rtp->ice_active_remote_candidates) {
		ao2_ref(rtp->ice_active_remote_candidates, -1);
		rtp->ice_active_remote_candidates = NULL;
	}

	if (rtp->ioqueue) {
		/*
		 * We cannot hold the instance lock because we could wait
		 * for the ioqueue thread to die and we might deadlock as
		 * a result.
		 */
		ao2_unlock(instance);
		rtp_ioqueue_thread_remove(rtp->ioqueue);
		ao2_lock(instance);
		rtp->ioqueue = NULL;
	}
#endif
}

/*! \pre instance is locked */
static int ast_rtp_new(struct ast_rtp_instance *instance,
		       struct ast_sched_context *sched, struct ast_sockaddr *addr,
		       void *data)
{
	struct ast_rtp *rtp = NULL;

	/* Create a new RTP structure to hold all of our data */
	if (!(rtp = ast_calloc(1, sizeof(*rtp)))) {
		return -1;
	}

	/* Set default parameters on the newly created RTP structure */
	rtp->ssrc = ast_random();
	ast_uuid_generate_str(rtp->cname, sizeof(rtp->cname));
	rtp->seqno = ast_random() & 0x7fff;
	rtp->expectedrxseqno = -1;
	rtp->expectedseqno = -1;
	rtp->sched = sched;
	ast_sockaddr_copy(&rtp->bind_address, addr);

	/* Transport creation operations can grab the RTP data from the instance, so set it */
	ast_rtp_instance_set_data(instance, rtp);

	if (rtp_allocate_transport(instance, rtp)) {
		return -1;
	}

	if (AST_VECTOR_INIT(&rtp->ssrc_mapping, 1)) {
		return -1;
	}

	rtp->f.subclass.format = ao2_bump(ast_format_none);
	rtp->lastrxformat = ao2_bump(ast_format_none);
	rtp->lasttxformat = ao2_bump(ast_format_none);
	rtp->stream_num = -1;

	return 0;
}

/*!
 * \brief SSRC mapping comparator for AST_VECTOR_REMOVE_CMP_UNORDERED()
 *
 * \param elem Element to compare against
 * \param value Value to compare with the vector element.
 *
 * \return 0 if element does not match.
 * \return Non-zero if element matches.
 */
#define SSRC_MAPPING_ELEM_CMP(elem, value) ((elem).instance == (value))

/*! \pre instance is locked */
static int ast_rtp_destroy(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (rtp->bundled) {
		struct ast_rtp *bundled_rtp;

		/* We can't hold our instance lock while removing ourselves from the parent */
		ao2_unlock(instance);

		ao2_lock(rtp->bundled);
		bundled_rtp = ast_rtp_instance_get_data(rtp->bundled);
		AST_VECTOR_REMOVE_CMP_UNORDERED(&bundled_rtp->ssrc_mapping, instance, SSRC_MAPPING_ELEM_CMP, AST_VECTOR_ELEM_CLEANUP_NOOP);
		ao2_unlock(rtp->bundled);

		ao2_lock(instance);
		ao2_ref(rtp->bundled, -1);
	}

	rtp_deallocate_transport(instance, rtp);

	/* Destroy the smoother that was smoothing out audio if present */
	if (rtp->smoother) {
		ast_smoother_free(rtp->smoother);
	}

	/* Destroy RTCP if it was being used */
	if (rtp->rtcp) {
		/*
		 * It is not possible for there to be an active RTCP scheduler
		 * entry at this point since it holds a reference to the
		 * RTP instance while it's active.
		 */
		ast_free(rtp->rtcp->local_addr_str);
		ast_free(rtp->rtcp);
	}

	/* Destroy RED if it was being used */
	if (rtp->red) {
		ao2_unlock(instance);
		AST_SCHED_DEL(rtp->sched, rtp->red->schedid);
		ao2_lock(instance);
		ast_free(rtp->red);
		rtp->red = NULL;
	}

	/* Destroy the send buffer if it was being used */
	if (rtp->send_buffer) {
		ast_data_buffer_free(rtp->send_buffer);
	}

	/* Destroy the recv buffer if it was being used */
	if (rtp->recv_buffer) {
		ast_data_buffer_free(rtp->recv_buffer);
	}

	ao2_cleanup(rtp->lasttxformat);
	ao2_cleanup(rtp->lastrxformat);
	ao2_cleanup(rtp->f.subclass.format);
	AST_VECTOR_FREE(&rtp->ssrc_mapping);
	AST_VECTOR_FREE(&rtp->missing_seqno);

	/* Finally destroy ourselves */
	ast_free(rtp);

	return 0;
}

/*! \pre instance is locked */
static int ast_rtp_dtmf_mode_set(struct ast_rtp_instance *instance, enum ast_rtp_dtmf_mode dtmf_mode)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	rtp->dtmfmode = dtmf_mode;
	return 0;
}

/*! \pre instance is locked */
static enum ast_rtp_dtmf_mode ast_rtp_dtmf_mode_get(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	return rtp->dtmfmode;
}

/*! \pre instance is locked */
static int ast_rtp_dtmf_begin(struct ast_rtp_instance *instance, char digit)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };
	int hdrlen = 12, res = 0, i = 0, payload = 101;
	char data[256];
	unsigned int *rtpheader = (unsigned int*)data;

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* If we have no remote address information bail out now */
	if (ast_sockaddr_isnull(&remote_address)) {
		return -1;
	}

	/* Convert given digit into what we want to transmit */
	if ((digit <= '9') && (digit >= '0')) {
		digit -= '0';
	} else if (digit == '*') {
		digit = 10;
	} else if (digit == '#') {
		digit = 11;
	} else if ((digit >= 'A') && (digit <= 'D')) {
		digit = digit - 'A' + 12;
	} else if ((digit >= 'a') && (digit <= 'd')) {
		digit = digit - 'a' + 12;
	} else {
		ast_log(LOG_WARNING, "Don't know how to represent '%c'\n", digit);
		return -1;
	}

	/* Grab the payload that they expect the RFC2833 packet to be received in */
	payload = ast_rtp_codecs_payload_code_tx(ast_rtp_instance_get_codecs(instance), 0, NULL, AST_RTP_DTMF);

	rtp->dtmfmute = ast_tvadd(ast_tvnow(), ast_tv(0, 500000));
	rtp->send_duration = 160;
	rtp->lastts += calc_txstamp(rtp, NULL) * DTMF_SAMPLE_RATE_MS;
	rtp->lastdigitts = rtp->lastts + rtp->send_duration;

	/* Create the actual packet that we will be sending */
	rtpheader[0] = htonl((2 << 30) | (1 << 23) | (payload << 16) | (rtp->seqno));
	rtpheader[1] = htonl(rtp->lastdigitts);
	rtpheader[2] = htonl(rtp->ssrc);

	/* Actually send the packet */
	for (i = 0; i < 2; i++) {
		int ice;

		rtpheader[3] = htonl((digit << 24) | (0xa << 16) | (rtp->send_duration));
		res = rtp_sendto(instance, (void *) rtpheader, hdrlen + 4, 0, &remote_address, &ice);
		if (res < 0) {
			ast_log(LOG_ERROR, "RTP Transmission error to %s: %s\n",
				ast_sockaddr_stringify(&remote_address),
				strerror(errno));
		}
		if (rtp_debug_test_addr(&remote_address)) {
			ast_verbose("Sent RTP DTMF packet to %s%s (type %-2.2d, seq %-6.6d, ts %-6.6u, len %-6.6d)\n",
				    ast_sockaddr_stringify(&remote_address),
				    ice ? " (via ICE)" : "",
				    payload, rtp->seqno, rtp->lastdigitts, res - hdrlen);
		}
		rtp->seqno++;
		rtp->send_duration += 160;
		rtpheader[0] = htonl((2 << 30) | (payload << 16) | (rtp->seqno));
	}

	/* Record that we are in the process of sending a digit and information needed to continue doing so */
	rtp->sending_digit = 1;
	rtp->send_digit = digit;
	rtp->send_payload = payload;

	return 0;
}

/*! \pre instance is locked */
static int ast_rtp_dtmf_continuation(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };
	int hdrlen = 12, res = 0;
	char data[256];
	unsigned int *rtpheader = (unsigned int*)data;
	int ice;

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* Make sure we know where the other side is so we can send them the packet */
	if (ast_sockaddr_isnull(&remote_address)) {
		return -1;
	}

	/* Actually create the packet we will be sending */
	rtpheader[0] = htonl((2 << 30) | (rtp->send_payload << 16) | (rtp->seqno));
	rtpheader[1] = htonl(rtp->lastdigitts);
	rtpheader[2] = htonl(rtp->ssrc);
	rtpheader[3] = htonl((rtp->send_digit << 24) | (0xa << 16) | (rtp->send_duration));

	/* Boom, send it on out */
	res = rtp_sendto(instance, (void *) rtpheader, hdrlen + 4, 0, &remote_address, &ice);
	if (res < 0) {
		ast_log(LOG_ERROR, "RTP Transmission error to %s: %s\n",
			ast_sockaddr_stringify(&remote_address),
			strerror(errno));
	}

	if (rtp_debug_test_addr(&remote_address)) {
		ast_verbose("Sent RTP DTMF packet to %s%s (type %-2.2d, seq %-6.6d, ts %-6.6u, len %-6.6d)\n",
			    ast_sockaddr_stringify(&remote_address),
			    ice ? " (via ICE)" : "",
			    rtp->send_payload, rtp->seqno, rtp->lastdigitts, res - hdrlen);
	}

	/* And now we increment some values for the next time we swing by */
	rtp->seqno++;
	rtp->send_duration += 160;
	rtp->lastts += calc_txstamp(rtp, NULL) * DTMF_SAMPLE_RATE_MS;

	return 0;
}

/*! \pre instance is locked */
static int ast_rtp_dtmf_end_with_duration(struct ast_rtp_instance *instance, char digit, unsigned int duration)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };
	int hdrlen = 12, res = -1, i = 0;
	char data[256];
	unsigned int *rtpheader = (unsigned int*)data;
	unsigned int measured_samples;

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* Make sure we know where the remote side is so we can send them the packet we construct */
	if (ast_sockaddr_isnull(&remote_address)) {
		goto cleanup;
	}

	/* Convert the given digit to the one we are going to send */
	if ((digit <= '9') && (digit >= '0')) {
		digit -= '0';
	} else if (digit == '*') {
		digit = 10;
	} else if (digit == '#') {
		digit = 11;
	} else if ((digit >= 'A') && (digit <= 'D')) {
		digit = digit - 'A' + 12;
	} else if ((digit >= 'a') && (digit <= 'd')) {
		digit = digit - 'a' + 12;
	} else {
		ast_log(LOG_WARNING, "Don't know how to represent '%c'\n", digit);
		goto cleanup;
	}

	rtp->dtmfmute = ast_tvadd(ast_tvnow(), ast_tv(0, 500000));

	if (duration > 0 && (measured_samples = duration * rtp_get_rate(rtp->f.subclass.format) / 1000) > rtp->send_duration) {
		ast_debug(2, "Adjusting final end duration from %d to %u\n", rtp->send_duration, measured_samples);
		rtp->send_duration = measured_samples;
	}

	/* Construct the packet we are going to send */
	rtpheader[1] = htonl(rtp->lastdigitts);
	rtpheader[2] = htonl(rtp->ssrc);
	rtpheader[3] = htonl((digit << 24) | (0xa << 16) | (rtp->send_duration));
	rtpheader[3] |= htonl((1 << 23));

	/* Send it 3 times, that's the magical number */
	for (i = 0; i < 3; i++) {
		int ice;

		rtpheader[0] = htonl((2 << 30) | (rtp->send_payload << 16) | (rtp->seqno));

		res = rtp_sendto(instance, (void *) rtpheader, hdrlen + 4, 0, &remote_address, &ice);

		if (res < 0) {
			ast_log(LOG_ERROR, "RTP Transmission error to %s: %s\n",
				ast_sockaddr_stringify(&remote_address),
				strerror(errno));
		}

		if (rtp_debug_test_addr(&remote_address)) {
			ast_verbose("Sent RTP DTMF packet to %s%s (type %-2.2d, seq %-6.6d, ts %-6.6u, len %-6.6d)\n",
				    ast_sockaddr_stringify(&remote_address),
				    ice ? " (via ICE)" : "",
				    rtp->send_payload, rtp->seqno, rtp->lastdigitts, res - hdrlen);
		}

		rtp->seqno++;
	}
	res = 0;

	/* Oh and we can't forget to turn off the stuff that says we are sending DTMF */
	rtp->lastts += calc_txstamp(rtp, NULL) * DTMF_SAMPLE_RATE_MS;

	/* Reset the smoother as the delivery time stored in it is now out of date */
	if (rtp->smoother) {
		ast_smoother_free(rtp->smoother);
		rtp->smoother = NULL;
	}
cleanup:
	rtp->sending_digit = 0;
	rtp->send_digit = 0;

	return res;
}

/*! \pre instance is locked */
static int ast_rtp_dtmf_end(struct ast_rtp_instance *instance, char digit)
{
	return ast_rtp_dtmf_end_with_duration(instance, digit, 0);
}

/*! \pre instance is locked */
static void ast_rtp_update_source(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	/* We simply set this bit so that the next packet sent will have the marker bit turned on */
	ast_set_flag(rtp, FLAG_NEED_MARKER_BIT);
	ast_debug(3, "Setting the marker bit due to a source update\n");

	return;
}

/*! \pre instance is locked */
static void ast_rtp_change_source(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_srtp *srtp = ast_rtp_instance_get_srtp(instance, 0);
	struct ast_srtp *rtcp_srtp = ast_rtp_instance_get_srtp(instance, 1);
	unsigned int ssrc = ast_random();

	if (rtp->lastts) {
		/* We simply set this bit so that the next packet sent will have the marker bit turned on */
		ast_set_flag(rtp, FLAG_NEED_MARKER_BIT);
	}

	ast_debug(3, "Changing ssrc from %u to %u due to a source change\n", rtp->ssrc, ssrc);

	if (srtp) {
		ast_debug(3, "Changing ssrc for SRTP from %u to %u\n", rtp->ssrc, ssrc);
		res_srtp->change_source(srtp, rtp->ssrc, ssrc);
		if (rtcp_srtp != srtp) {
			res_srtp->change_source(rtcp_srtp, rtp->ssrc, ssrc);
		}
	}

	rtp->ssrc = ssrc;

	/* Since the source is changing, we don't know what sequence number to expect next */
	rtp->expectedrxseqno = -1;

	return;
}

static void timeval2ntp(struct timeval tv, unsigned int *msw, unsigned int *lsw)
{
	unsigned int sec, usec, frac;
	sec = tv.tv_sec + 2208988800u; /* Sec between 1900 and 1970 */
	usec = tv.tv_usec;
	/*
	 * Convert usec to 0.32 bit fixed point without overflow.
	 *
	 * = usec * 2^32 / 10^6
	 * = usec * 2^32 / (2^6 * 5^6)
	 * = usec * 2^26 / 5^6
	 *
	 * The usec value needs 20 bits to represent 999999 usec.  So
	 * splitting the 2^26 to get the most precision using 32 bit
	 * values gives:
	 *
	 * = ((usec * 2^12) / 5^6) * 2^14
	 *
	 * Splitting the division into two stages preserves all the
	 * available significant bits of usec over doing the division
	 * all at once.
	 *
	 * = ((((usec * 2^12) / 5^3) * 2^7) / 5^3) * 2^7
	 */
	frac = ((((usec << 12) / 125) << 7) / 125) << 7;
	*msw = sec;
	*lsw = frac;
}

static void ntp2timeval(unsigned int msw, unsigned int lsw, struct timeval *tv)
{
	tv->tv_sec = msw - 2208988800u;
	/* Reverse the sequence in timeval2ntp() */
	tv->tv_usec = ((((lsw >> 7) * 125) >> 7) * 125) >> 12;
}

static void calculate_lost_packet_statistics(struct ast_rtp *rtp,
		unsigned int *lost_packets,
		int *fraction_lost)
{
	unsigned int extended_seq_no;
	unsigned int expected_packets;
	unsigned int expected_interval;
	unsigned int received_interval;
	double rxlost_current;
	int lost_interval;

	/* Compute statistics */
	extended_seq_no = rtp->cycles + rtp->lastrxseqno;
	expected_packets = extended_seq_no - rtp->seedrxseqno + 1;
	if (rtp->rxcount > expected_packets) {
		expected_packets += rtp->rxcount - expected_packets;
	}
	*lost_packets = expected_packets - rtp->rxcount;
	expected_interval = expected_packets - rtp->rtcp->expected_prior;
	received_interval = rtp->rxcount - rtp->rtcp->received_prior;
	lost_interval = expected_interval - received_interval;
	if (expected_interval == 0 || lost_interval <= 0) {
		*fraction_lost = 0;
	} else {
		*fraction_lost = (lost_interval << 8) / expected_interval;
	}

	/* Update RTCP statistics */
	rtp->rtcp->received_prior = rtp->rxcount;
	rtp->rtcp->expected_prior = expected_packets;
	if (lost_interval <= 0) {
		rtp->rtcp->rxlost = 0;
	} else {
		rtp->rtcp->rxlost = lost_interval;
	}
	if (rtp->rtcp->rxlost_count == 0) {
		rtp->rtcp->minrxlost = rtp->rtcp->rxlost;
	}
	if (lost_interval < rtp->rtcp->minrxlost) {
		rtp->rtcp->minrxlost = rtp->rtcp->rxlost;
	}
	if (lost_interval > rtp->rtcp->maxrxlost) {
		rtp->rtcp->maxrxlost = rtp->rtcp->rxlost;
	}
	rxlost_current = normdev_compute(rtp->rtcp->normdev_rxlost,
			rtp->rtcp->rxlost,
			rtp->rtcp->rxlost_count);
	rtp->rtcp->stdev_rxlost = stddev_compute(rtp->rtcp->stdev_rxlost,
			rtp->rtcp->rxlost,
			rtp->rtcp->normdev_rxlost,
			rxlost_current,
			rtp->rtcp->rxlost_count);
	rtp->rtcp->normdev_rxlost = rxlost_current;
	rtp->rtcp->rxlost_count++;
}

static int ast_rtcp_generate_report(struct ast_rtp_instance *instance, unsigned char *rtcpheader,
		struct ast_rtp_rtcp_report *rtcp_report, int *sr)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int len = 0;
	struct timeval now;
	unsigned int now_lsw;
	unsigned int now_msw;
	unsigned int lost_packets;
	int fraction_lost;
	struct timeval dlsr = { 0, };
	struct ast_rtp_rtcp_report_block *report_block = NULL;

	if (!rtp || !rtp->rtcp) {
		return 0;
	}

	if (ast_sockaddr_isnull(&rtp->rtcp->them)) { /* This'll stop rtcp for this rtp session */
		/* RTCP was stopped. */
		return 0;
	}

	if (!rtcp_report) {
		return 1;
	}

	*sr = rtp->txcount > rtp->rtcp->lastsrtxcount ? 1 : 0;

	/* Compute statistics */
	calculate_lost_packet_statistics(rtp, &lost_packets, &fraction_lost);

	gettimeofday(&now, NULL);
	rtcp_report->reception_report_count = rtp->themssrc_valid ? 1 : 0;
	rtcp_report->ssrc = rtp->ssrc;
	rtcp_report->type = *sr ? RTCP_PT_SR : RTCP_PT_RR;
	if (*sr) {
		rtcp_report->sender_information.ntp_timestamp = now;
		rtcp_report->sender_information.rtp_timestamp = rtp->lastts;
		rtcp_report->sender_information.packet_count = rtp->txcount;
		rtcp_report->sender_information.octet_count = rtp->txoctetcount;
	}

	if (rtp->themssrc_valid) {
		report_block = ast_calloc(1, sizeof(*report_block));
		if (!report_block) {
			return 1;
		}

		rtcp_report->report_block[0] = report_block;
		report_block->source_ssrc = rtp->themssrc;
		report_block->lost_count.fraction = (fraction_lost & 0xff);
		report_block->lost_count.packets = (lost_packets & 0xffffff);
		report_block->highest_seq_no = (rtp->cycles | (rtp->lastrxseqno & 0xffff));
		report_block->ia_jitter = (unsigned int)(rtp->rxjitter * rtp_get_rate(rtp->f.subclass.format));
		report_block->lsr = rtp->rtcp->themrxlsr;
		/* If we haven't received an SR report, DLSR should be 0 */
		if (!ast_tvzero(rtp->rtcp->rxlsr)) {
			timersub(&now, &rtp->rtcp->rxlsr, &dlsr);
			report_block->dlsr = (((dlsr.tv_sec * 1000) + (dlsr.tv_usec / 1000)) * 65536) / 1000;
		}
	}
	timeval2ntp(rtcp_report->sender_information.ntp_timestamp, &now_msw, &now_lsw);
	put_unaligned_uint32(rtcpheader + 4, htonl(rtcp_report->ssrc)); /* Our SSRC */
	len += 8;
	if (*sr) {
		put_unaligned_uint32(rtcpheader + len, htonl(now_msw)); /* now, MSW. gettimeofday() + SEC_BETWEEN_1900_AND_1970 */
		put_unaligned_uint32(rtcpheader + len + 4, htonl(now_lsw)); /* now, LSW */
		put_unaligned_uint32(rtcpheader + len + 8, htonl(rtcp_report->sender_information.rtp_timestamp));
		put_unaligned_uint32(rtcpheader + len + 12, htonl(rtcp_report->sender_information.packet_count));
		put_unaligned_uint32(rtcpheader + len + 16, htonl(rtcp_report->sender_information.octet_count));
		len += 20;
	}
	if (report_block) {
		put_unaligned_uint32(rtcpheader + len, htonl(report_block->source_ssrc)); /* Their SSRC */
		put_unaligned_uint32(rtcpheader + len + 4, htonl((report_block->lost_count.fraction << 24) | report_block->lost_count.packets));
		put_unaligned_uint32(rtcpheader + len + 8, htonl(report_block->highest_seq_no));
		put_unaligned_uint32(rtcpheader + len + 12, htonl(report_block->ia_jitter));
		put_unaligned_uint32(rtcpheader + len + 16, htonl(report_block->lsr));
		put_unaligned_uint32(rtcpheader + len + 20, htonl(report_block->dlsr));
		len += 24;
	}

	put_unaligned_uint32(rtcpheader, htonl((2 << 30) | (rtcp_report->reception_report_count << 24)
				| ((*sr ? RTCP_PT_SR : RTCP_PT_RR) << 16) | ((len/4)-1)));

	return len;
}

static int ast_rtcp_calculate_sr_rr_statistics(struct ast_rtp_instance *instance,
		struct ast_rtp_rtcp_report *rtcp_report, struct ast_sockaddr remote_address, int ice, int sr)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_rtp_rtcp_report_block *report_block = NULL;
	RAII_VAR(struct ast_json *, message_blob, NULL, ast_json_unref);

	if (!rtp || !rtp->rtcp) {
		return 0;
	}

	if (ast_sockaddr_isnull(&rtp->rtcp->them)) {
		return 0;
	}

	if (!rtcp_report) {
		return -1;
	}

	report_block = rtcp_report->report_block[0];

	if (sr) {
		rtp->rtcp->txlsr = rtcp_report->sender_information.ntp_timestamp;
		rtp->rtcp->sr_count++;
		rtp->rtcp->lastsrtxcount = rtp->txcount;
	} else {
		rtp->rtcp->rr_count++;
	}

	if (rtcp_debug_test_addr(&rtp->rtcp->them)) {
		ast_verbose("* Sent RTCP %s to %s%s\n", sr ? "SR" : "RR",
				ast_sockaddr_stringify(&remote_address), ice ? " (via ICE)" : "");
		ast_verbose("  Our SSRC: %u\n", rtcp_report->ssrc);
		if (sr) {
			ast_verbose("  Sent(NTP): %u.%06u\n",
				(unsigned int)rtcp_report->sender_information.ntp_timestamp.tv_sec,
				(unsigned int)rtcp_report->sender_information.ntp_timestamp.tv_usec);
			ast_verbose("  Sent(RTP): %u\n", rtcp_report->sender_information.rtp_timestamp);
			ast_verbose("  Sent packets: %u\n", rtcp_report->sender_information.packet_count);
			ast_verbose("  Sent octets: %u\n", rtcp_report->sender_information.octet_count);
		}
		if (report_block) {
			ast_verbose("  Report block:\n");
			ast_verbose("    Their SSRC: %u\n", report_block->source_ssrc);
			ast_verbose("    Fraction lost: %d\n", report_block->lost_count.fraction);
			ast_verbose("    Cumulative loss: %u\n", report_block->lost_count.packets);
			ast_verbose("    Highest seq no: %u\n", report_block->highest_seq_no);
			ast_verbose("    IA jitter: %.4f\n", (double)report_block->ia_jitter / rtp_get_rate(rtp->f.subclass.format));
			ast_verbose("    Their last SR: %u\n", report_block->lsr);
			ast_verbose("    DLSR: %4.4f (sec)\n\n", (double)(report_block->dlsr / 65536.0));
		}
	}

	message_blob = ast_json_pack("{s: s, s: s}",
			"to", ast_sockaddr_stringify(&remote_address),
			"from", rtp->rtcp->local_addr_str);
	ast_rtp_publish_rtcp_message(instance, ast_rtp_rtcp_sent_type(),
			rtcp_report, message_blob);

	return 1;
}

static int ast_rtcp_generate_sdes(struct ast_rtp_instance *instance, unsigned char *rtcpheader,
		struct ast_rtp_rtcp_report *rtcp_report)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int len = 0;
	uint16_t sdes_packet_len_bytes;
	uint16_t sdes_packet_len_rounded;

	if (!rtp || !rtp->rtcp) {
		return 0;
	}

	if (ast_sockaddr_isnull(&rtp->rtcp->them)) {
		return 0;
	}

	if (!rtcp_report) {
		return -1;
	}

	sdes_packet_len_bytes =
		4 + /* RTCP Header */
		4 + /* SSRC */
		1 + /* Type (CNAME) */
		1 + /* Text Length */
		AST_UUID_STR_LEN /* Text and NULL terminator */
		;

	/* Round to 32 bit boundary */
	sdes_packet_len_rounded = (sdes_packet_len_bytes + 3) & ~0x3;

	put_unaligned_uint32(rtcpheader, htonl((2 << 30) | (1 << 24) | (RTCP_PT_SDES << 16) | ((sdes_packet_len_rounded / 4) - 1)));
	put_unaligned_uint32(rtcpheader + 4, htonl(rtcp_report->ssrc));
	rtcpheader[8] = 0x01; /* CNAME */
	rtcpheader[9] = AST_UUID_STR_LEN - 1; /* Number of bytes of text */
	memcpy(rtcpheader + 10, rtp->cname, AST_UUID_STR_LEN);
	len += 10 + AST_UUID_STR_LEN;

	/* Padding - Note that we don't set the padded bit on the packet. From
	 * RFC 3550 Section 6.5:
	 *
	 *   No length octet follows the null item type octet, but additional null
	 *   octets MUST be included if needd to pad until the next 32-bit
	 *   boundary. Note that this padding is separate from that indicated by
	 *   the P bit in the RTCP header.
	 *
	 * These bytes will already be zeroed out during array initialization.
	 */
	len += (sdes_packet_len_rounded - sdes_packet_len_bytes);

	return len;
}

static int ast_rtcp_generate_nack(struct ast_rtp_instance *instance, unsigned char *rtcpheader)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int packet_len;
	int blp_index;
	int current_seqno;
	int seqno;
	unsigned int fci;

	if (!rtp || !rtp->rtcp) {
		return 0;
	}

	if (ast_sockaddr_isnull(&rtp->rtcp->them)) {
		return 0;
	}

	current_seqno = rtp->expectedrxseqno;
	seqno = rtp->lastrxseqno;
	packet_len = 12; /* The header length is 12 (version line, packet source SSRC, media source SSRC) */

	/* Get the missing sequence numbers for the FCI section of the NACK request */
	for (blp_index = 0, fci = 0; current_seqno < seqno; current_seqno++, blp_index++) {
		int *missing_seqno;

		missing_seqno = AST_VECTOR_GET_CMP(&rtp->missing_seqno, current_seqno,
				find_by_value);

		if (!missing_seqno) {
			continue;
		}

		/* We hit the max blp size, reset */
		if (blp_index >= 17) {
			put_unaligned_uint32(rtcpheader + packet_len, htonl(fci));
			fci = 0;
			blp_index = 0;
			packet_len += 4;
		}

		if (blp_index == 0) {
			fci |= (current_seqno << 16);
		} else {
			fci |= (1 << (blp_index - 1));
		}
	}

	put_unaligned_uint32(rtcpheader + packet_len, htonl(fci));
	packet_len += 4;

	/* Length MUST be 2+n, where n is the number of NACKs. Same as length in words minus 1 */
	put_unaligned_uint32(rtcpheader, htonl((2 << 30) | (AST_RTP_RTCP_FMT_NACK << 24)
				| (AST_RTP_RTCP_RTPFB << 16) | ((packet_len / 4) - 1)));
	put_unaligned_uint32(rtcpheader + 4, htonl(rtp->ssrc));
	put_unaligned_uint32(rtcpheader + 8, htonl(rtp->themssrc));

	return packet_len;
}

/*!
 * \brief Write a RTCP packet to the far end
 *
 * \note Decide if we are going to send an SR (with Reception Block) or RR
 * RR is sent if we have not sent any rtp packets in the previous interval
 *
 * Scheduler callback
 */
static int ast_rtcp_write(const void *data)
{
	struct ast_rtp_instance *instance = (struct ast_rtp_instance *) data;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int res;
	int sr = 0;
	int packet_len = 0;
	int ice;
	struct ast_sockaddr remote_address = { { 0, } };
	unsigned char *rtcpheader;
	unsigned char bdata[AST_UUID_STR_LEN + 128] = ""; /* More than enough */
	RAII_VAR(struct ast_rtp_rtcp_report *, rtcp_report,
			ast_rtp_rtcp_report_alloc(rtp->themssrc_valid ? 1 : 0),
			ao2_cleanup);

	if (!rtp || !rtp->rtcp || rtp->rtcp->schedid == -1) {
		ao2_ref(instance, -1);
		return 0;
	}

	ao2_lock(instance);
	rtcpheader = bdata;

	res = ast_rtcp_generate_report(instance, rtcpheader, rtcp_report, &sr);

	if (res == 0 || res == 1) {
		ast_debug(1, "Failed to add %s report to RTCP packet!\n", sr ? "SR" : "RR");
		goto cleanup;
	}

	packet_len += res;

	res = ast_rtcp_generate_sdes(instance, rtcpheader + packet_len, rtcp_report);

	if (res == 0 || res == 1) {
		ast_debug(1, "Failed to add SDES to RTCP packet!\n");
		goto cleanup;
	}

	packet_len += res;

	if (rtp->bundled) {
		ast_rtp_instance_get_remote_address(instance, &remote_address);
	} else {
		ast_sockaddr_copy(&remote_address, &rtp->rtcp->them);
	}

	res = rtcp_sendto(instance, (unsigned int *)rtcpheader, packet_len, 0, &remote_address, &ice);
	if (res < 0) {
		ast_log(LOG_ERROR, "RTCP %s transmission error to %s, rtcp halted %s\n",
				sr ? "SR" : "RR",
				ast_sockaddr_stringify(&rtp->rtcp->them),
				strerror(errno));
		res = 0;
	} else {
		ast_rtcp_calculate_sr_rr_statistics(instance, rtcp_report, remote_address, ice, sr);
	}

cleanup:
	ao2_unlock(instance);

	if (!res) {
		/*
		 * Not being rescheduled.
		 */
		rtp->rtcp->schedid = -1;
		ao2_ref(instance, -1);
	}

	return res;
}

static void put_unaligned_time24(void *p, uint32_t time_msw, uint32_t time_lsw)
{
	unsigned char *cp = p;
	uint32_t datum;

	/* Convert the time to 6.18 format */
	datum = (time_msw << 18) & 0x00fc0000;
	datum |= (time_lsw >> 14) & 0x0003ffff;

	cp[0] = datum >> 16;
	cp[1] = datum >> 8;
	cp[2] = datum;
}

/*! \pre instance is locked */
static int rtp_raw_write(struct ast_rtp_instance *instance, struct ast_frame *frame, int codec)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int pred, mark = 0;
	unsigned int ms = calc_txstamp(rtp, &frame->delivery);
	struct ast_sockaddr remote_address = { {0,} };
	int rate = rtp_get_rate(frame->subclass.format) / 1000;
	unsigned int seqno;

	if (ast_format_cmp(frame->subclass.format, ast_format_g722) == AST_FORMAT_CMP_EQUAL) {
		frame->samples /= 2;
	}

	if (rtp->sending_digit) {
		return 0;
	}

	if (frame->frametype == AST_FRAME_VOICE) {
		pred = rtp->lastts + frame->samples;

		/* Re-calculate last TS */
		rtp->lastts = rtp->lastts + ms * rate;
		if (ast_tvzero(frame->delivery)) {
			/* If this isn't an absolute delivery time, Check if it is close to our prediction,
			   and if so, go with our prediction */
			if (abs((int)rtp->lastts - pred) < MAX_TIMESTAMP_SKEW) {
				rtp->lastts = pred;
			} else {
				ast_debug(3, "Difference is %d, ms is %u\n", abs((int)rtp->lastts - pred), ms);
				mark = 1;
			}
		}
	} else if (frame->frametype == AST_FRAME_VIDEO) {
		mark = frame->subclass.frame_ending;
		pred = rtp->lastovidtimestamp + frame->samples;
		/* Re-calculate last TS */
		rtp->lastts = rtp->lastts + ms * 90;
		/* If it's close to our prediction, go for it */
		if (ast_tvzero(frame->delivery)) {
			if (abs((int)rtp->lastts - pred) < 7200) {
				rtp->lastts = pred;
				rtp->lastovidtimestamp += frame->samples;
			} else {
				ast_debug(3, "Difference is %d, ms is %u (%u), pred/ts/samples %u/%d/%d\n", abs((int)rtp->lastts - pred), ms, ms * 90, rtp->lastts, pred, frame->samples);
				rtp->lastovidtimestamp = rtp->lastts;
			}
		}
	} else {
		pred = rtp->lastotexttimestamp + frame->samples;
		/* Re-calculate last TS */
		rtp->lastts = rtp->lastts + ms;
		/* If it's close to our prediction, go for it */
		if (ast_tvzero(frame->delivery)) {
			if (abs((int)rtp->lastts - pred) < 7200) {
				rtp->lastts = pred;
				rtp->lastotexttimestamp += frame->samples;
			} else {
				ast_debug(3, "Difference is %d, ms is %u, pred/ts/samples %u/%d/%d\n", abs((int)rtp->lastts - pred), ms, rtp->lastts, pred, frame->samples);
				rtp->lastotexttimestamp = rtp->lastts;
			}
		}
	}

	/* If we have been explicitly told to set the marker bit then do so */
	if (ast_test_flag(rtp, FLAG_NEED_MARKER_BIT)) {
		mark = 1;
		ast_clear_flag(rtp, FLAG_NEED_MARKER_BIT);
	}

	/* If the timestamp for non-digt packets has moved beyond the timestamp for digits, update the digit timestamp */
	if (rtp->lastts > rtp->lastdigitts) {
		rtp->lastdigitts = rtp->lastts;
	}

	/* Assume that the sequence number we expect to use is what will be used until proven otherwise */
	seqno = rtp->seqno;

	/* If the frame contains sequence number information use it to influence our sequence number */
	if (ast_test_flag(frame, AST_FRFLAG_HAS_SEQUENCE_NUMBER)) {
		if (rtp->expectedseqno != -1) {
			/* Determine where the frame from the core is in relation to where we expected */
			int difference = frame->seqno - rtp->expectedseqno;

			/* If there is a substantial difference then we've either got packets really out
			 * of order, or the source is RTP and it has cycled. If this happens we resync
			 * the sequence number adjustments to this frame. If we also have packet loss
			 * things won't be reflected correctly but it will sort itself out after a bit.
			 */
			if (abs(difference) > 100) {
				difference = 0;
			}

			/* Adjust the sequence number being used for this packet accordingly */
			seqno += difference;

			if (difference >= 0) {
				/* This frame is on time or in the future */
				rtp->expectedseqno = frame->seqno + 1;
				rtp->seqno += difference;
			}
		} else {
			/* This is the first frame with sequence number we've seen, so start keeping track */
			rtp->expectedseqno = frame->seqno + 1;
		}
	} else {
		rtp->expectedseqno = -1;
	}

	if (ast_test_flag(frame, AST_FRFLAG_HAS_TIMING_INFO)) {
		rtp->lastts = frame->ts * rate;
	}

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* If we know the remote address construct a packet and send it out */
	if (!ast_sockaddr_isnull(&remote_address)) {
		int hdrlen = 12;
		int res;
		int ice;
		int ext = 0;
		int abs_send_time_id;
		int packet_len;
		unsigned char *rtpheader;

		/* If the abs-send-time extension has been negotiated determine how much space we need */
		abs_send_time_id = ast_rtp_instance_extmap_get_id(instance, AST_RTP_EXTENSION_ABS_SEND_TIME);
		if (abs_send_time_id != -1) {
			/* 4 bytes for the shared information, 1 byte for identifier, 3 bytes for abs-send-time */
			hdrlen += 8;
			ext = 1;
		}

		packet_len = frame->datalen + hdrlen;
		rtpheader = (unsigned char *)(frame->data.ptr - hdrlen);

		put_unaligned_uint32(rtpheader, htonl((2 << 30) | (ext << 28) | (codec << 16) | (seqno) | (mark << 23)));
		put_unaligned_uint32(rtpheader + 4, htonl(rtp->lastts));
		put_unaligned_uint32(rtpheader + 8, htonl(rtp->ssrc));

		/* We assume right now that we will only ever have the abs-send-time extension in the packet
		 * which simplifies things a bit.
		 */
		if (abs_send_time_id != -1) {
			unsigned int now_msw;
			unsigned int now_lsw;

			/* This happens before being placed into the retransmission buffer so that when we
			 * retransmit we only have to update the timestamp, not everything else.
			 */
			put_unaligned_uint32(rtpheader + 12, htonl((0xBEDE << 16) | 1));
			rtpheader[16] = (abs_send_time_id << 4) | 2;

			timeval2ntp(ast_tvnow(), &now_msw, &now_lsw);
			put_unaligned_time24(rtpheader + 17, now_msw, now_lsw);
		}

		/* If retransmissions are enabled, we need to store this packet for future use */
		if (rtp->send_buffer) {
			struct ast_rtp_rtcp_nack_payload *payload;

			payload = ast_malloc(sizeof(*payload) + packet_len);
			if (payload) {
				payload->size = packet_len;
				memcpy(payload->buf, rtpheader, packet_len);
				ast_data_buffer_put(rtp->send_buffer, rtp->seqno, payload);
			}
		}

		res = rtp_sendto(instance, (void *)rtpheader, packet_len, 0, &remote_address, &ice);
		if (res < 0) {
			if (!ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_NAT) || (ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_NAT) && (ast_test_flag(rtp, FLAG_NAT_ACTIVE) == FLAG_NAT_ACTIVE))) {
				ast_debug(1, "RTP Transmission error of packet %d to %s: %s\n",
					  rtp->seqno,
					  ast_sockaddr_stringify(&remote_address),
					  strerror(errno));
			} else if (((ast_test_flag(rtp, FLAG_NAT_ACTIVE) == FLAG_NAT_INACTIVE) || rtpdebug) && !ast_test_flag(rtp, FLAG_NAT_INACTIVE_NOWARN)) {
				/* Only give this error message once if we are not RTP debugging */
				if (rtpdebug)
					ast_debug(0, "RTP NAT: Can't write RTP to private address %s, waiting for other end to send audio...\n",
						  ast_sockaddr_stringify(&remote_address));
				ast_set_flag(rtp, FLAG_NAT_INACTIVE_NOWARN);
			}
		} else {
			if (rtp->rtcp && rtp->rtcp->schedid < 0) {
				ast_debug(1, "Starting RTCP transmission on RTP instance '%p'\n", instance);
				ao2_ref(instance, +1);
				rtp->rtcp->schedid = ast_sched_add(rtp->sched, ast_rtcp_calc_interval(rtp), ast_rtcp_write, instance);
				if (rtp->rtcp->schedid < 0) {
					ao2_ref(instance, -1);
					ast_log(LOG_WARNING, "scheduling RTCP transmission failed.\n");
				}
			}
		}

		if (rtp_debug_test_addr(&remote_address)) {
			ast_verbose("Sent RTP packet to      %s%s (type %-2.2d, seq %-6.6d, ts %-6.6u, len %-6.6d)\n",
				    ast_sockaddr_stringify(&remote_address),
				    ice ? " (via ICE)" : "",
				    codec, rtp->seqno, rtp->lastts, res - hdrlen);
		}
	}

	/* If the sequence number that has been used doesn't match what we expected then this is an out of
	 * order late packet, so we don't need to increment as we haven't yet gotten the expected frame from
	 * the core.
	 */
	if (seqno == rtp->seqno) {
		rtp->seqno++;
	}

	return 0;
}

static struct ast_frame *red_t140_to_red(struct rtp_red *red)
{
	unsigned char *data = red->t140red.data.ptr;
	int len = 0;
	int i;

	/* replace most aged generation */
	if (red->len[0]) {
		for (i = 1; i < red->num_gen+1; i++)
			len += red->len[i];

		memmove(&data[red->hdrlen], &data[red->hdrlen+red->len[0]], len);
	}

	/* Store length of each generation and primary data length*/
	for (i = 0; i < red->num_gen; i++)
		red->len[i] = red->len[i+1];
	red->len[i] = red->t140.datalen;

	/* write each generation length in red header */
	len = red->hdrlen;
	for (i = 0; i < red->num_gen; i++) {
		len += data[i*4+3] = red->len[i];
	}

	/* add primary data to buffer */
	memcpy(&data[len], red->t140.data.ptr, red->t140.datalen);
	red->t140red.datalen = len + red->t140.datalen;

	/* no primary data and no generations to send */
	if (len == red->hdrlen && !red->t140.datalen) {
		return NULL;
	}

	/* reset t.140 buffer */
	red->t140.datalen = 0;

	return &red->t140red;
}

static void rtp_write_rtcp_fir(struct ast_rtp_instance *instance, struct ast_rtp *rtp, struct ast_sockaddr *remote_address)
{
	unsigned int *rtcpheader;
	char bdata[1024];
	int len = 20;
	int ice;
	int res;

	if (!rtp || !rtp->rtcp) {
		return;
	}

	if (ast_sockaddr_isnull(&rtp->rtcp->them) || rtp->rtcp->schedid < 0) {
		/*
		 * RTCP was stopped.
		 */
		return;
	}

	if (!rtp->themssrc_valid) {
		/* We don't know their SSRC value so we don't know who to update. */
		return;
	}

	/* Prepare RTCP FIR (PT=206, FMT=4) */
	rtp->rtcp->firseq++;
	if(rtp->rtcp->firseq == 256) {
		rtp->rtcp->firseq = 0;
	}

	rtcpheader = (unsigned int *)bdata;
	rtcpheader[0] = htonl((2 << 30) | (4 << 24) | (RTCP_PT_PSFB << 16) | ((len/4)-1));
	rtcpheader[1] = htonl(rtp->ssrc);
	rtcpheader[2] = htonl(rtp->themssrc);
	rtcpheader[3] = htonl(rtp->themssrc);	/* FCI: SSRC */
	rtcpheader[4] = htonl(rtp->rtcp->firseq << 24);			/* FCI: Sequence number */
	res = rtcp_sendto(instance, (unsigned int *)rtcpheader, len, 0, rtp->bundled ? remote_address : &rtp->rtcp->them, &ice);
	if (res < 0) {
		ast_log(LOG_ERROR, "RTCP FIR transmission error: %s\n", strerror(errno));
	}
}

static void rtp_write_rtcp_psfb(struct ast_rtp_instance *instance, struct ast_rtp *rtp, struct ast_frame *frame, struct ast_sockaddr *remote_address)
{
	struct ast_rtp_rtcp_feedback *feedback = frame->data.ptr;
	unsigned int *rtcpheader;
	char bdata[1024];
	int len = 24;
	int ice;
	int res;

	if (feedback->fmt != AST_RTP_RTCP_FMT_REMB) {
		ast_debug(1, "Provided an RTCP feedback frame of format %d to write on RTP instance '%p' but only REMB is supported\n",
			feedback->fmt, instance);
		return;
	}

	if (!rtp || !rtp->rtcp) {
		return;
	}

	/* If REMB support is not enabled don't send this RTCP packet */
	if (!ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_REMB)) {
		ast_debug(1, "Provided an RTCP feedback REMB report to write on RTP instance '%p' but REMB support not enabled\n",
			instance);
		return;
	}

	if (ast_sockaddr_isnull(&rtp->rtcp->them) || rtp->rtcp->schedid < 0) {
		/*
		 * RTCP was stopped.
		 */
		return;
	}

	rtcpheader = (unsigned int *)bdata;
	rtcpheader[0] = htonl((2 << 30) | (AST_RTP_RTCP_FMT_REMB << 24) | (RTCP_PT_PSFB << 16) | ((len/4)-1));
	rtcpheader[1] = htonl(rtp->ssrc);
	rtcpheader[2] = htonl(0); /* Per the draft this should always be 0 */
	rtcpheader[3] = htonl(('R' << 24) | ('E' << 16) | ('M' << 8) | ('B')); /* Unique identifier 'R' 'E' 'M' 'B' */
	rtcpheader[4] = htonl((1 << 24) | (feedback->remb.br_exp << 18) | (feedback->remb.br_mantissa)); /* Number of SSRCs / BR Exp / BR Mantissa */
	rtcpheader[5] = htonl(rtp->ssrc); /* The SSRC this feedback message applies to */
	res = rtcp_sendto(instance, (unsigned int *)rtcpheader, len, 0, rtp->bundled ? remote_address : &rtp->rtcp->them, &ice);
	if (res < 0) {
		ast_log(LOG_ERROR, "RTCP PSFB transmission error: %s\n", strerror(errno));
	}
}

/*! \pre instance is locked */
static int ast_rtp_write(struct ast_rtp_instance *instance, struct ast_frame *frame)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };
	struct ast_format *format;
	int codec;

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* If we don't actually know the remote address don't even bother doing anything */
	if (ast_sockaddr_isnull(&remote_address)) {
		ast_debug(1, "No remote address on RTP instance '%p' so dropping frame\n", instance);
		return 0;
	}

	/* VP8: is this a request to send a RTCP FIR? */
	if (frame->frametype == AST_FRAME_CONTROL && frame->subclass.integer == AST_CONTROL_VIDUPDATE) {
		rtp_write_rtcp_fir(instance, rtp, &remote_address);
		return 0;
	} else if (frame->frametype == AST_FRAME_RTCP) {
		if (frame->subclass.integer == AST_RTP_RTCP_PSFB) {
			rtp_write_rtcp_psfb(instance, rtp, frame, &remote_address);
		}
		return 0;
	}

	/* If there is no data length we can't very well send the packet */
	if (!frame->datalen) {
		ast_debug(1, "Received frame with no data for RTP instance '%p' so dropping frame\n", instance);
		return 0;
	}

	/* If the packet is not one our RTP stack supports bail out */
	if (frame->frametype != AST_FRAME_VOICE && frame->frametype != AST_FRAME_VIDEO && frame->frametype != AST_FRAME_TEXT) {
		ast_log(LOG_WARNING, "RTP can only send voice, video, and text\n");
		return -1;
	}

	if (rtp->red) {
		/* return 0; */
		/* no primary data or generations to send */
		if ((frame = red_t140_to_red(rtp->red)) == NULL)
			return 0;
	}

	/* Grab the subclass and look up the payload we are going to use */
	codec = ast_rtp_codecs_payload_code_tx(ast_rtp_instance_get_codecs(instance),
		1, frame->subclass.format, 0);
	if (codec < 0) {
		ast_log(LOG_WARNING, "Don't know how to send format %s packets with RTP\n",
			ast_format_get_name(frame->subclass.format));
		return -1;
	}

	/* Note that we do not increase the ref count here as this pointer
	 * will not be held by any thing explicitly. The format variable is
	 * merely a convenience reference to frame->subclass.format */
	format = frame->subclass.format;
	if (ast_format_cmp(rtp->lasttxformat, format) == AST_FORMAT_CMP_NOT_EQUAL) {
		/* Oh dear, if the format changed we will have to set up a new smoother */
		ast_debug(1, "Ooh, format changed from %s to %s\n",
			ast_format_get_name(rtp->lasttxformat),
			ast_format_get_name(frame->subclass.format));
		ao2_replace(rtp->lasttxformat, format);
		if (rtp->smoother) {
			ast_smoother_free(rtp->smoother);
			rtp->smoother = NULL;
		}
	}

	/* If no smoother is present see if we have to set one up */
	if (!rtp->smoother && ast_format_can_be_smoothed(format)) {
		unsigned int smoother_flags = ast_format_get_smoother_flags(format);
		unsigned int framing_ms = ast_rtp_codecs_get_framing(ast_rtp_instance_get_codecs(instance));

		if (!framing_ms && (smoother_flags & AST_SMOOTHER_FLAG_FORCED)) {
			framing_ms = ast_format_get_default_ms(format);
		}

		if (framing_ms) {
			rtp->smoother = ast_smoother_new((framing_ms * ast_format_get_minimum_bytes(format)) / ast_format_get_minimum_ms(format));
			if (!rtp->smoother) {
				ast_log(LOG_WARNING, "Unable to create smoother: format %s ms: %u len: %u\n",
					ast_format_get_name(format), framing_ms, ast_format_get_minimum_bytes(format));
				return -1;
			}
			ast_smoother_set_flags(rtp->smoother, smoother_flags);
		}
	}

	/* Feed audio frames into the actual function that will create a frame and send it */
	if (rtp->smoother) {
		struct ast_frame *f;

		if (ast_smoother_test_flag(rtp->smoother, AST_SMOOTHER_FLAG_BE)) {
			ast_smoother_feed_be(rtp->smoother, frame);
		} else {
			ast_smoother_feed(rtp->smoother, frame);
		}

		while ((f = ast_smoother_read(rtp->smoother)) && (f->data.ptr)) {
				rtp_raw_write(instance, f, codec);
		}
	} else {
		int hdrlen = 12;
		struct ast_frame *f = NULL;

		if (frame->offset < hdrlen) {
			f = ast_frdup(frame);
		} else {
			f = frame;
		}
		if (f->data.ptr) {
			rtp_raw_write(instance, f, codec);
		}
		if (f != frame) {
			ast_frfree(f);
		}

	}

	return 0;
}

static void calc_rxstamp(struct timeval *tv, struct ast_rtp *rtp, unsigned int timestamp, int mark)
{
	struct timeval now;
	struct timeval tmp;
	double transit;
	double current_time;
	double d;
	double dtv;
	double prog;
	int rate = rtp_get_rate(rtp->f.subclass.format);

	double normdev_rxjitter_current;
	if ((!rtp->rxcore.tv_sec && !rtp->rxcore.tv_usec) || mark) {
		gettimeofday(&rtp->rxcore, NULL);
		rtp->drxcore = (double) rtp->rxcore.tv_sec + (double) rtp->rxcore.tv_usec / 1000000;
		/* map timestamp to a real time */
		rtp->seedrxts = timestamp; /* Their RTP timestamp started with this */
		tmp = ast_samp2tv(timestamp, rate);
		rtp->rxcore = ast_tvsub(rtp->rxcore, tmp);
		/* Round to 0.1ms for nice, pretty timestamps */
		rtp->rxcore.tv_usec -= rtp->rxcore.tv_usec % 100;
	}

	gettimeofday(&now,NULL);
	/* rxcore is the mapping between the RTP timestamp and _our_ real time from gettimeofday() */
	tmp = ast_samp2tv(timestamp, rate);
	*tv = ast_tvadd(rtp->rxcore, tmp);

	prog = (double)((timestamp-rtp->seedrxts)/(float)(rate));
	dtv = (double)rtp->drxcore + (double)(prog);
	current_time = (double)now.tv_sec + (double)now.tv_usec/1000000;
	transit = current_time - dtv;
	d = transit - rtp->rxtransit;
	rtp->rxtransit = transit;
	if (d<0) {
		d=-d;
	}
	rtp->rxjitter += (1./16.) * (d - rtp->rxjitter);
	if (rtp->rtcp) {
		if (rtp->rxjitter > rtp->rtcp->maxrxjitter)
			rtp->rtcp->maxrxjitter = rtp->rxjitter;
		if (rtp->rtcp->rxjitter_count == 1)
			rtp->rtcp->minrxjitter = rtp->rxjitter;
		if (rtp->rtcp && rtp->rxjitter < rtp->rtcp->minrxjitter)
			rtp->rtcp->minrxjitter = rtp->rxjitter;

		normdev_rxjitter_current = normdev_compute(rtp->rtcp->normdev_rxjitter,rtp->rxjitter,rtp->rtcp->rxjitter_count);
		rtp->rtcp->stdev_rxjitter = stddev_compute(rtp->rtcp->stdev_rxjitter,rtp->rxjitter,rtp->rtcp->normdev_rxjitter,normdev_rxjitter_current,rtp->rtcp->rxjitter_count);

		rtp->rtcp->normdev_rxjitter = normdev_rxjitter_current;
		rtp->rtcp->rxjitter_count++;
	}
}

static struct ast_frame *create_dtmf_frame(struct ast_rtp_instance *instance, enum ast_frame_type type, int compensate)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	if (((compensate && type == AST_FRAME_DTMF_END) || (type == AST_FRAME_DTMF_BEGIN)) && ast_tvcmp(ast_tvnow(), rtp->dtmfmute) < 0) {
		ast_debug(1, "Ignore potential DTMF echo from '%s'\n",
			  ast_sockaddr_stringify(&remote_address));
		rtp->resp = 0;
		rtp->dtmfsamples = 0;
		return &ast_null_frame;
	}
	ast_debug(1, "Creating %s DTMF Frame: %d (%c), at %s\n",
		type == AST_FRAME_DTMF_END ? "END" : "BEGIN",
		rtp->resp, rtp->resp,
		ast_sockaddr_stringify(&remote_address));
	if (rtp->resp == 'X') {
		rtp->f.frametype = AST_FRAME_CONTROL;
		rtp->f.subclass.integer = AST_CONTROL_FLASH;
	} else {
		rtp->f.frametype = type;
		rtp->f.subclass.integer = rtp->resp;
	}
	rtp->f.datalen = 0;
	rtp->f.samples = 0;
	rtp->f.mallocd = 0;
	rtp->f.src = "RTP";
	AST_LIST_NEXT(&rtp->f, frame_list) = NULL;

	return &rtp->f;
}

static void process_dtmf_rfc2833(struct ast_rtp_instance *instance, unsigned char *data, int len, unsigned int seqno, unsigned int timestamp, int payloadtype, int mark, struct frame_list *frames)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };
	unsigned int event, event_end, samples;
	char resp = 0;
	struct ast_frame *f = NULL;

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/* Figure out event, event end, and samples */
	event = ntohl(*((unsigned int *)(data)));
	event >>= 24;
	event_end = ntohl(*((unsigned int *)(data)));
	event_end <<= 8;
	event_end >>= 24;
	samples = ntohl(*((unsigned int *)(data)));
	samples &= 0xFFFF;

	if (rtp_debug_test_addr(&remote_address)) {
		ast_verbose("Got  RTP RFC2833 from   %s (type %-2.2d, seq %-6.6u, ts %-6.6u, len %-6.6d, mark %d, event %08x, end %d, duration %-5.5u) \n",
			    ast_sockaddr_stringify(&remote_address),
			    payloadtype, seqno, timestamp, len, (mark?1:0), event, ((event_end & 0x80)?1:0), samples);
	}

	/* Print out debug if turned on */
	if (rtpdebug)
		ast_debug(0, "- RTP 2833 Event: %08x (len = %d)\n", event, len);

	/* Figure out what digit was pressed */
	if (event < 10) {
		resp = '0' + event;
	} else if (event < 11) {
		resp = '*';
	} else if (event < 12) {
		resp = '#';
	} else if (event < 16) {
		resp = 'A' + (event - 12);
	} else if (event < 17) {        /* Event 16: Hook flash */
		resp = 'X';
	} else {
		/* Not a supported event */
		ast_debug(1, "Ignoring RTP 2833 Event: %08x. Not a DTMF Digit.\n", event);
		return;
	}

	if (ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_DTMF_COMPENSATE)) {
		if ((rtp->last_end_timestamp != timestamp) || (rtp->resp && rtp->resp != resp)) {
			rtp->resp = resp;
			rtp->dtmf_timeout = 0;
			f = ast_frdup(create_dtmf_frame(instance, AST_FRAME_DTMF_END, ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_DTMF_COMPENSATE)));
			f->len = 0;
			rtp->last_end_timestamp = timestamp;
			AST_LIST_INSERT_TAIL(frames, f, frame_list);
		}
	} else {
		/*  The duration parameter measures the complete
		    duration of the event (from the beginning) - RFC2833.
		    Account for the fact that duration is only 16 bits long
		    (about 8 seconds at 8000 Hz) and can wrap is digit
		    is hold for too long. */
		unsigned int new_duration = rtp->dtmf_duration;
		unsigned int last_duration = new_duration & 0xFFFF;

		if (last_duration > 64000 && samples < last_duration) {
			new_duration += 0xFFFF + 1;
		}
		new_duration = (new_duration & ~0xFFFF) | samples;

		if (event_end & 0x80) {
			/* End event */
			if ((rtp->last_seqno != seqno) && (timestamp > rtp->last_end_timestamp)) {
				rtp->last_end_timestamp = timestamp;
				rtp->dtmf_duration = new_duration;
				rtp->resp = resp;
				f = ast_frdup(create_dtmf_frame(instance, AST_FRAME_DTMF_END, 0));
				f->len = ast_tvdiff_ms(ast_samp2tv(rtp->dtmf_duration, rtp_get_rate(f->subclass.format)), ast_tv(0, 0));
				rtp->resp = 0;
				rtp->dtmf_duration = rtp->dtmf_timeout = 0;
				AST_LIST_INSERT_TAIL(frames, f, frame_list);
			} else if (rtpdebug) {
				ast_debug(1, "Dropping duplicate or out of order DTMF END frame (seqno: %u, ts %u, digit %c)\n",
					seqno, timestamp, resp);
			}
		} else {
			/* Begin/continuation */

			/* The second portion of the seqno check is to not mistakenly
			 * stop accepting DTMF if the seqno rolls over beyond
			 * 65535.
			 */
			if ((rtp->last_seqno > seqno && rtp->last_seqno - seqno < 50)
				|| timestamp <= rtp->last_end_timestamp) {
				/* Out of order frame. Processing this can cause us to
				 * improperly duplicate incoming DTMF, so just drop
				 * this.
				 */
				if (rtpdebug) {
					ast_debug(1, "Dropping out of order DTMF frame (seqno %u, ts %u, digit %c)\n",
						seqno, timestamp, resp);
				}
				return;
			}

			if (rtp->resp && rtp->resp != resp) {
				/* Another digit already began. End it */
				f = ast_frdup(create_dtmf_frame(instance, AST_FRAME_DTMF_END, 0));
				f->len = ast_tvdiff_ms(ast_samp2tv(rtp->dtmf_duration, rtp_get_rate(f->subclass.format)), ast_tv(0, 0));
				rtp->resp = 0;
				rtp->dtmf_duration = rtp->dtmf_timeout = 0;
				AST_LIST_INSERT_TAIL(frames, f, frame_list);
			}

			if (rtp->resp) {
				/* Digit continues */
				rtp->dtmf_duration = new_duration;
			} else {
				/* New digit began */
				rtp->resp = resp;
				f = ast_frdup(create_dtmf_frame(instance, AST_FRAME_DTMF_BEGIN, 0));
				rtp->dtmf_duration = samples;
				AST_LIST_INSERT_TAIL(frames, f, frame_list);
			}

			rtp->dtmf_timeout = timestamp + rtp->dtmf_duration + dtmftimeout;
		}

		rtp->last_seqno = seqno;
	}

	rtp->dtmfsamples = samples;

	return;
}

static struct ast_frame *process_dtmf_cisco(struct ast_rtp_instance *instance, unsigned char *data, int len, unsigned int seqno, unsigned int timestamp, int payloadtype, int mark)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	unsigned int event, flags, power;
	char resp = 0;
	unsigned char seq;
	struct ast_frame *f = NULL;

	if (len < 4) {
		return NULL;
	}

	/*      The format of Cisco RTP DTMF packet looks like next:
		+0                              - sequence number of DTMF RTP packet (begins from 1,
						  wrapped to 0)
		+1                              - set of flags
		+1 (bit 0)              - flaps by different DTMF digits delimited by audio
						  or repeated digit without audio???
		+2 (+4,+6,...)  - power level? (rises from 0 to 32 at begin of tone
						  then falls to 0 at its end)
		+3 (+5,+7,...)  - detected DTMF digit (0..9,*,#,A-D,...)
		Repeated DTMF information (bytes 4/5, 6/7) is history shifted right
		by each new packet and thus provides some redudancy.

		Sample of Cisco RTP DTMF packet is (all data in hex):
			19 07 00 02 12 02 20 02
		showing end of DTMF digit '2'.

		The packets
			27 07 00 02 0A 02 20 02
			28 06 20 02 00 02 0A 02
		shows begin of new digit '2' with very short pause (20 ms) after
		previous digit '2'. Bit +1.0 flips at begin of new digit.

		Cisco RTP DTMF packets comes as replacement of audio RTP packets
		so its uses the same sequencing and timestamping rules as replaced
		audio packets. Repeat interval of DTMF packets is 20 ms and not rely
		on audio framing parameters. Marker bit isn't used within stream of
		DTMFs nor audio stream coming immediately after DTMF stream. Timestamps
		are not sequential at borders between DTMF and audio streams,
	*/

	seq = data[0];
	flags = data[1];
	power = data[2];
	event = data[3] & 0x1f;

	if (rtpdebug)
		ast_debug(0, "Cisco DTMF Digit: %02x (len=%d, seq=%d, flags=%02x, power=%u, history count=%d)\n", event, len, seq, flags, power, (len - 4) / 2);
	if (event < 10) {
		resp = '0' + event;
	} else if (event < 11) {
		resp = '*';
	} else if (event < 12) {
		resp = '#';
	} else if (event < 16) {
		resp = 'A' + (event - 12);
	} else if (event < 17) {
		resp = 'X';
	}
	if ((!rtp->resp && power) || (rtp->resp && (rtp->resp != resp))) {
		rtp->resp = resp;
		/* Why we should care on DTMF compensation at reception? */
		if (ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_DTMF_COMPENSATE)) {
			f = create_dtmf_frame(instance, AST_FRAME_DTMF_BEGIN, 0);
			rtp->dtmfsamples = 0;
		}
	} else if ((rtp->resp == resp) && !power) {
		f = create_dtmf_frame(instance, AST_FRAME_DTMF_END, ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_DTMF_COMPENSATE));
		f->samples = rtp->dtmfsamples * (rtp_get_rate(rtp->lastrxformat) / 1000);
		rtp->resp = 0;
	} else if (rtp->resp == resp) {
		rtp->dtmfsamples += 20 * (rtp_get_rate(rtp->lastrxformat) / 1000);
	}

	rtp->dtmf_timeout = 0;

	return f;
}

static struct ast_frame *process_cn_rfc3389(struct ast_rtp_instance *instance, unsigned char *data, int len, unsigned int seqno, unsigned int timestamp, int payloadtype, int mark)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	/* Convert comfort noise into audio with various codecs.  Unfortunately this doesn't
	   totally help us out becuase we don't have an engine to keep it going and we are not
	   guaranteed to have it every 20ms or anything */
	if (rtpdebug) {
		ast_debug(0, "- RTP 3389 Comfort noise event: Format %s (len = %d)\n",
			ast_format_get_name(rtp->lastrxformat), len);
	}

	if (ast_test_flag(rtp, FLAG_3389_WARNING)) {
		struct ast_sockaddr remote_address = { {0,} };

		ast_rtp_instance_get_remote_address(instance, &remote_address);

		ast_log(LOG_NOTICE, "Comfort noise support incomplete in Asterisk (RFC 3389). Please turn off on client if possible. Client address: %s\n",
			ast_sockaddr_stringify(&remote_address));
		ast_set_flag(rtp, FLAG_3389_WARNING);
	}

	/* Must have at least one byte */
	if (!len) {
		return NULL;
	}
	if (len < 24) {
		rtp->f.data.ptr = rtp->rawdata + AST_FRIENDLY_OFFSET;
		rtp->f.datalen = len - 1;
		rtp->f.offset = AST_FRIENDLY_OFFSET;
		memcpy(rtp->f.data.ptr, data + 1, len - 1);
	} else {
		rtp->f.data.ptr = NULL;
		rtp->f.offset = 0;
		rtp->f.datalen = 0;
	}
	rtp->f.frametype = AST_FRAME_CNG;
	rtp->f.subclass.integer = data[0] & 0x7f;
	rtp->f.samples = 0;
	rtp->f.delivery.tv_usec = rtp->f.delivery.tv_sec = 0;

	return &rtp->f;
}

static int update_rtt_stats(struct ast_rtp *rtp, unsigned int lsr, unsigned int dlsr)
{
	struct timeval now;
	struct timeval rtt_tv;
	unsigned int msw;
	unsigned int lsw;
	unsigned int rtt_msw;
	unsigned int rtt_lsw;
	unsigned int lsr_a;
	unsigned int rtt;
	double normdevrtt_current;

	gettimeofday(&now, NULL);
	timeval2ntp(now, &msw, &lsw);

	lsr_a = ((msw & 0x0000ffff) << 16) | ((lsw & 0xffff0000) >> 16);
	rtt = lsr_a - lsr - dlsr;
	rtt_msw = (rtt & 0xffff0000) >> 16;
	rtt_lsw = (rtt & 0x0000ffff);
	rtt_tv.tv_sec = rtt_msw;
	/*
	 * Convert 16.16 fixed point rtt_lsw to usec without
	 * overflow.
	 *
	 * = rtt_lsw * 10^6 / 2^16
	 * = rtt_lsw * (2^6 * 5^6) / 2^16
	 * = rtt_lsw * 5^6 / 2^10
	 *
	 * The rtt_lsw value is in 16.16 fixed point format and 5^6
	 * requires 14 bits to represent.  We have enough space to
	 * directly do the conversion because there is no integer
	 * component in rtt_lsw.
	 */
	rtt_tv.tv_usec = (rtt_lsw * 15625) >> 10;
	rtp->rtcp->rtt = (double)rtt_tv.tv_sec + ((double)rtt_tv.tv_usec / 1000000);
	if (lsr_a - dlsr < lsr) {
		return 1;
	}

	rtp->rtcp->accumulated_transit += rtp->rtcp->rtt;
	if (rtp->rtcp->rtt_count == 0 || rtp->rtcp->minrtt > rtp->rtcp->rtt) {
		rtp->rtcp->minrtt = rtp->rtcp->rtt;
	}
	if (rtp->rtcp->maxrtt < rtp->rtcp->rtt) {
		rtp->rtcp->maxrtt = rtp->rtcp->rtt;
	}

	normdevrtt_current = normdev_compute(rtp->rtcp->normdevrtt,
			rtp->rtcp->rtt,
			rtp->rtcp->rtt_count);
	rtp->rtcp->stdevrtt = stddev_compute(rtp->rtcp->stdevrtt,
			rtp->rtcp->rtt,
			rtp->rtcp->normdevrtt,
			normdevrtt_current,
			rtp->rtcp->rtt_count);
	rtp->rtcp->normdevrtt = normdevrtt_current;
	rtp->rtcp->rtt_count++;

	return 0;
}

/*!
 * \internal
 * \brief Update RTCP interarrival jitter stats
 */
static void update_jitter_stats(struct ast_rtp *rtp, unsigned int ia_jitter)
{
	double reported_jitter;
	double reported_normdev_jitter_current;

	rtp->rtcp->reported_jitter = ia_jitter;
	reported_jitter = (double) rtp->rtcp->reported_jitter;
	if (rtp->rtcp->reported_jitter_count == 0) {
		rtp->rtcp->reported_minjitter = reported_jitter;
	}
	if (reported_jitter < rtp->rtcp->reported_minjitter) {
		rtp->rtcp->reported_minjitter = reported_jitter;
	}
	if (reported_jitter > rtp->rtcp->reported_maxjitter) {
		rtp->rtcp->reported_maxjitter = reported_jitter;
	}
	reported_normdev_jitter_current = normdev_compute(rtp->rtcp->reported_normdev_jitter, reported_jitter, rtp->rtcp->reported_jitter_count);
	rtp->rtcp->reported_stdev_jitter = stddev_compute(rtp->rtcp->reported_stdev_jitter, reported_jitter, rtp->rtcp->reported_normdev_jitter, reported_normdev_jitter_current, rtp->rtcp->reported_jitter_count);
	rtp->rtcp->reported_normdev_jitter = reported_normdev_jitter_current;
}

/*!
 * \internal
 * \brief Update RTCP lost packet stats
 */
static void update_lost_stats(struct ast_rtp *rtp, unsigned int lost_packets)
{
	double reported_lost;
	double reported_normdev_lost_current;

	rtp->rtcp->reported_lost = lost_packets;
	reported_lost = (double)rtp->rtcp->reported_lost;
	if (rtp->rtcp->reported_jitter_count == 0) {
		rtp->rtcp->reported_minlost = reported_lost;
	}
	if (reported_lost < rtp->rtcp->reported_minlost) {
		rtp->rtcp->reported_minlost = reported_lost;
	}
	if (reported_lost > rtp->rtcp->reported_maxlost) {
		rtp->rtcp->reported_maxlost = reported_lost;
	}
	reported_normdev_lost_current = normdev_compute(rtp->rtcp->reported_normdev_lost, reported_lost, rtp->rtcp->reported_jitter_count);
	rtp->rtcp->reported_stdev_lost = stddev_compute(rtp->rtcp->reported_stdev_lost, reported_lost, rtp->rtcp->reported_normdev_lost, reported_normdev_lost_current, rtp->rtcp->reported_jitter_count);
	rtp->rtcp->reported_normdev_lost = reported_normdev_lost_current;
}

/*! \pre instance is locked */
static struct ast_rtp_instance *__rtp_find_instance_by_ssrc(struct ast_rtp_instance *instance,
	struct ast_rtp *rtp, unsigned int ssrc, int source)
{
	int index;

	if (!AST_VECTOR_SIZE(&rtp->ssrc_mapping)) {
		/* This instance is not bundled */
		return instance;
	}

	/* Find the bundled child instance */
	for (index = 0; index < AST_VECTOR_SIZE(&rtp->ssrc_mapping); ++index) {
		struct rtp_ssrc_mapping *mapping = AST_VECTOR_GET_ADDR(&rtp->ssrc_mapping, index);
		unsigned int mapping_ssrc = source ? ast_rtp_get_ssrc(mapping->instance) : mapping->ssrc;

		if (mapping->ssrc_valid && mapping_ssrc == ssrc) {
			return mapping->instance;
		}
	}

	/* Does the SSRC match the bundled parent? */
	if (rtp->themssrc_valid && rtp->themssrc == ssrc) {
		return instance;
	}
	return NULL;
}

/*! \pre instance is locked */
static struct ast_rtp_instance *rtp_find_instance_by_packet_source_ssrc(struct ast_rtp_instance *instance,
	struct ast_rtp *rtp, unsigned int ssrc)
{
	return __rtp_find_instance_by_ssrc(instance, rtp, ssrc, 0);
}

/*! \pre instance is locked */
static struct ast_rtp_instance *rtp_find_instance_by_media_source_ssrc(struct ast_rtp_instance *instance,
	struct ast_rtp *rtp, unsigned int ssrc)
{
	return __rtp_find_instance_by_ssrc(instance, rtp, ssrc, 1);
}

static const char *rtcp_payload_type2str(unsigned int pt)
{
	const char *str;

	switch (pt) {
	case RTCP_PT_SR:
		str = "Sender Report";
		break;
	case RTCP_PT_RR:
		str = "Receiver Report";
		break;
	case RTCP_PT_FUR:
		/* Full INTRA-frame Request / Fast Update Request */
		str = "H.261 FUR";
		break;
	case RTCP_PT_PSFB:
		/* Payload Specific Feed Back */
		str = "PSFB";
		break;
	case RTCP_PT_SDES:
		str = "Source Description";
		break;
	case RTCP_PT_BYE:
		str = "BYE";
		break;
	default:
		str = "Unknown";
		break;
	}
	return str;
}

/*! \pre instance is locked */
static int ast_rtp_rtcp_handle_nack(struct ast_rtp_instance *instance, unsigned int *nackdata, unsigned int position,
	unsigned int length)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int res = 0;
	int blp_index;
	int packet_index;
	int ice;
	struct ast_rtp_rtcp_nack_payload *payload;
	unsigned int current_word;
	unsigned int pid;	/* Packet ID which refers to seqno of lost packet */
	unsigned int blp;	/* Bitmask of following lost packets */
	struct ast_sockaddr remote_address = { {0,} };
	int abs_send_time_id;
	unsigned int now_msw = 0;
	unsigned int now_lsw = 0;

	if (!rtp->send_buffer) {
		ast_debug(1, "Tried to handle NACK request, but we don't have a RTP packet storage!\n");
		return res;
	}

	abs_send_time_id = ast_rtp_instance_extmap_get_id(instance, AST_RTP_EXTENSION_ABS_SEND_TIME);
	if (abs_send_time_id != -1) {
		timeval2ntp(ast_tvnow(), &now_msw, &now_lsw);
	}

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	/*
	 * We use index 3 because with feedback messages, the FCI (Feedback Control Information)
	 * does not begin until after the version, packet SSRC, and media SSRC words.
	 */
	for (packet_index = 3; packet_index < length; packet_index++) {
		current_word = ntohl(nackdata[position + packet_index]);
		pid = current_word >> 16;
		/* We know the remote end is missing this packet. Go ahead and send it if we still have it. */
		payload = (struct ast_rtp_rtcp_nack_payload *)ast_data_buffer_get(rtp->send_buffer, pid);
		if (payload) {
			if (abs_send_time_id != -1) {
				/* On retransmission we need to update the timestamp within the packet, as it
				 * is supposed to contain when the packet was actually sent.
				 */
				put_unaligned_time24(payload->buf + 17, now_msw, now_lsw);
			}
			res += rtp_sendto(instance, payload->buf, payload->size, 0, &remote_address, &ice);
		} else {
			ast_debug(1, "Received NACK request for RTP packet with seqno %d, but we don't have it\n", pid);
		}
		/*
		 * The bitmask. Denoting the least significant bit as 1 and its most significant bit
		 * as 16, then bit i of the bitmask is set to 1 if the receiver has not received RTP
		 * packet (pid+i)(modulo 2^16). Otherwise, it is set to 0. We cannot assume bits set
		 * to 0 after a bit set to 1 have actually been received.
		 */
		blp = current_word & 0xFF;
		blp_index = 1;
		while (blp) {
			if (blp & 1) {
				/* Packet (pid + i)(modulo 2^16) is missing too. */
				unsigned int seqno = (pid + blp_index) % 65536;
				payload = (struct ast_rtp_rtcp_nack_payload *)ast_data_buffer_get(rtp->send_buffer, seqno);
				if (payload) {
					if (abs_send_time_id != -1) {
						put_unaligned_time24(payload->buf + 17, now_msw, now_lsw);
					}
					res += rtp_sendto(instance, payload->buf, payload->size, 0, &remote_address, &ice);
				} else {
					ast_debug(1, "Remote end also requested RTP packet with seqno %d, but we don't have it\n", seqno);
				}
			}
			blp >>= 1;
			blp_index++;
		}
	}

	return res;
}

/*
 * Unshifted RTCP header bit field masks
 */
#define RTCP_LENGTH_MASK			0xFFFF
#define RTCP_PAYLOAD_TYPE_MASK		0xFF
#define RTCP_REPORT_COUNT_MASK		0x1F
#define RTCP_PADDING_MASK			0x01
#define RTCP_VERSION_MASK			0x03

/*
 * RTCP header bit field shift offsets
 */
#define RTCP_LENGTH_SHIFT			0
#define RTCP_PAYLOAD_TYPE_SHIFT		16
#define RTCP_REPORT_COUNT_SHIFT		24
#define RTCP_PADDING_SHIFT			29
#define RTCP_VERSION_SHIFT			30

#define RTCP_VERSION				2U
#define RTCP_VERSION_SHIFTED		(RTCP_VERSION << RTCP_VERSION_SHIFT)
#define RTCP_VERSION_MASK_SHIFTED	(RTCP_VERSION_MASK << RTCP_VERSION_SHIFT)

/*
 * RTCP first packet record validity header mask and value.
 *
 * RFC3550 intentionally defines the encoding of RTCP_PT_SR and RTCP_PT_RR
 * such that they differ in the least significant bit.  Either of these two
 * payload types MUST be the first RTCP packet record in a compound packet.
 *
 * RFC3550 checks the padding bit in the algorithm they use to check the
 * RTCP packet for validity.  However, we aren't masking the padding bit
 * to check since we don't know if it is a compound RTCP packet or not.
 */
#define RTCP_VALID_MASK (RTCP_VERSION_MASK_SHIFTED | (((RTCP_PAYLOAD_TYPE_MASK & ~0x1)) << RTCP_PAYLOAD_TYPE_SHIFT))
#define RTCP_VALID_VALUE (RTCP_VERSION_SHIFTED | (RTCP_PT_SR << RTCP_PAYLOAD_TYPE_SHIFT))

#define RTCP_SR_BLOCK_WORD_LENGTH 5
#define RTCP_RR_BLOCK_WORD_LENGTH 6
#define RTCP_HEADER_SSRC_LENGTH   2
#define RTCP_FB_REMB_BLOCK_WORD_LENGTH 4
#define RTCP_FB_NACK_BLOCK_WORD_LENGTH 2

static struct ast_frame *ast_rtcp_interpret(struct ast_rtp_instance *instance, struct ast_srtp *srtp,
	const unsigned char *rtcpdata, size_t size, struct ast_sockaddr *addr)
{
	struct ast_rtp_instance *transport = instance;
	struct ast_rtp *transport_rtp = ast_rtp_instance_get_data(instance);
	int len = size;
	unsigned int *rtcpheader = (unsigned int *)(rtcpdata);
	unsigned int packetwords;
	unsigned int position;
	unsigned int first_word;
	/*! True if we have seen an acceptable SSRC to learn the remote RTCP address */
	unsigned int ssrc_seen;
	struct ast_rtp_rtcp_report_block *report_block;
	struct ast_frame *f = &ast_null_frame;

	/* If this is encrypted then decrypt the payload */
	if ((*rtcpheader & 0xC0) && res_srtp && srtp && res_srtp->unprotect(
		    srtp, rtcpheader, &len, 1) < 0) {
	   return &ast_null_frame;
	}

	packetwords = len / 4;

	ast_debug(1, "Got RTCP report of %d bytes from %s\n",
		len, ast_sockaddr_stringify(addr));

	/*
	 * Validate the RTCP packet according to an adapted and slightly
	 * modified RFC3550 validation algorithm.
	 */
	if (packetwords < RTCP_HEADER_SSRC_LENGTH) {
		ast_debug(1, "%p -- RTCP from %s: Frame size (%u words) is too short\n",
			transport_rtp, ast_sockaddr_stringify(addr), packetwords);
		return &ast_null_frame;
	}
	position = 0;
	first_word = ntohl(rtcpheader[position]);
	if ((first_word & RTCP_VALID_MASK) != RTCP_VALID_VALUE) {
		ast_debug(1, "%p -- RTCP from %s: Failed first packet validity check\n",
			transport_rtp, ast_sockaddr_stringify(addr));
		return &ast_null_frame;
	}
	do {
		position += ((first_word >> RTCP_LENGTH_SHIFT) & RTCP_LENGTH_MASK) + 1;
		if (packetwords <= position) {
			break;
		}
		first_word = ntohl(rtcpheader[position]);
	} while ((first_word & RTCP_VERSION_MASK_SHIFTED) == RTCP_VERSION_SHIFTED);
	if (position != packetwords) {
		ast_debug(1, "%p -- RTCP from %s: Failed packet version or length check\n",
			transport_rtp, ast_sockaddr_stringify(addr));
		return &ast_null_frame;
	}

	/*
	 * Note: RFC3605 points out that true NAT (vs NAPT) can cause RTCP
	 * to have a different IP address and port than RTP.  Otherwise, when
	 * strictrtp is enabled we could reject RTCP packets not coming from
	 * the learned RTP IP address if it is available.
	 */

	/*
	 * strictrtp safety needs SSRC to match before we use the
	 * sender's address for symmetrical RTP to send our RTCP
	 * reports.
	 *
	 * If strictrtp is not enabled then claim to have already seen
	 * a matching SSRC so we'll accept this packet's address for
	 * symmetrical RTP.
	 */
	ssrc_seen = transport_rtp->strict_rtp_state == STRICT_RTP_OPEN;

	position = 0;
	while (position < packetwords) {
		unsigned int i;
		unsigned int pt;
		unsigned int rc;
		unsigned int ssrc;
		/*! True if the ssrc value we have is valid and not garbage because it doesn't exist. */
		unsigned int ssrc_valid;
		unsigned int length;
		unsigned int min_length;
		/*! Always use packet source SSRC to find the rtp instance unless explicitly told not to. */
		unsigned int use_packet_source = 1;

		struct ast_json *message_blob;
		RAII_VAR(struct ast_rtp_rtcp_report *, rtcp_report, NULL, ao2_cleanup);
		struct ast_rtp_instance *child;
		struct ast_rtp *rtp;
		struct ast_rtp_rtcp_feedback *feedback;

		i = position;
		first_word = ntohl(rtcpheader[i]);
		pt = (first_word >> RTCP_PAYLOAD_TYPE_SHIFT) & RTCP_PAYLOAD_TYPE_MASK;
		rc = (first_word >> RTCP_REPORT_COUNT_SHIFT) & RTCP_REPORT_COUNT_MASK;
		/* RFC3550 says 'length' is the number of words in the packet - 1 */
		length = ((first_word >> RTCP_LENGTH_SHIFT) & RTCP_LENGTH_MASK) + 1;

		/* Check expected RTCP packet record length */
		min_length = RTCP_HEADER_SSRC_LENGTH;
		switch (pt) {
		case RTCP_PT_SR:
			min_length += RTCP_SR_BLOCK_WORD_LENGTH;
			/* fall through */
		case RTCP_PT_RR:
			min_length += (rc * RTCP_RR_BLOCK_WORD_LENGTH);
			use_packet_source = 0;
			break;
		case RTCP_PT_FUR:
			break;
		case AST_RTP_RTCP_RTPFB:
			switch (rc) {
			case AST_RTP_RTCP_FMT_NACK:
				min_length += RTCP_FB_NACK_BLOCK_WORD_LENGTH;
				break;
			default:
				break;
			}
			use_packet_source = 0;
			break;
		case RTCP_PT_PSFB:
			switch (rc) {
			case AST_RTP_RTCP_FMT_REMB:
				min_length += RTCP_FB_REMB_BLOCK_WORD_LENGTH;
				break;
			default:
				break;
			}
			break;
		case RTCP_PT_SDES:
		case RTCP_PT_BYE:
			/*
			 * There may not be a SSRC/CSRC present.  The packet is
			 * useless but still valid if it isn't present.
			 *
			 * We don't know what min_length should be so disable the check
			 */
			min_length = length;
			break;
		default:
			ast_debug(1, "%p -- RTCP from %s: %u(%s) skipping record\n",
				transport_rtp, ast_sockaddr_stringify(addr), pt, rtcp_payload_type2str(pt));
			if (rtcp_debug_test_addr(addr)) {
				ast_verbose("\n");
				ast_verbose("RTCP from %s: %u(%s) skipping record\n",
					ast_sockaddr_stringify(addr), pt, rtcp_payload_type2str(pt));
			}
			position += length;
			continue;
		}
		if (length < min_length) {
			ast_debug(1, "%p -- RTCP from %s: %u(%s) length field less than expected minimum.  Min:%u Got:%u\n",
				transport_rtp, ast_sockaddr_stringify(addr), pt, rtcp_payload_type2str(pt),
				min_length - 1, length - 1);
			return &ast_null_frame;
		}

		/* Get the RTCP record SSRC if defined for the record */
		ssrc_valid = 1;
		switch (pt) {
		case RTCP_PT_SR:
		case RTCP_PT_RR:
			rtcp_report = ast_rtp_rtcp_report_alloc(rc);
			if (!rtcp_report) {
				return &ast_null_frame;
			}
			rtcp_report->reception_report_count = rc;

			ssrc = ntohl(rtcpheader[i + 2]);
			rtcp_report->ssrc = ssrc;
			break;
		case RTCP_PT_FUR:
		case RTCP_PT_PSFB:
			ssrc = ntohl(rtcpheader[i + 1]);
			break;
		case AST_RTP_RTCP_RTPFB:
			ssrc = ntohl(rtcpheader[i + 2]);
			break;
		case RTCP_PT_SDES:
		case RTCP_PT_BYE:
		default:
			ssrc = 0;
			ssrc_valid = 0;
			break;
		}

		if (rtcp_debug_test_addr(addr)) {
			ast_verbose("\n");
			ast_verbose("RTCP from %s\n", ast_sockaddr_stringify(addr));
			ast_verbose("PT: %u(%s)\n", pt, rtcp_payload_type2str(pt));
			ast_verbose("Reception reports: %u\n", rc);
			ast_verbose("SSRC of sender: %u\n", ssrc);
		}

		/* Determine the appropriate instance for this */
		if (ssrc_valid) {
			/*
			 * Depending on the payload type, either the packet source or media source
			 * SSRC is used.
			 */
			if (use_packet_source) {
				child = rtp_find_instance_by_packet_source_ssrc(transport, transport_rtp, ssrc);
			} else {
				child = rtp_find_instance_by_media_source_ssrc(transport, transport_rtp, ssrc);
			}
			if (child && child != transport) {
				/*
				 * It is safe to hold the child lock while holding the parent lock.
				 * We guarantee that the locking order is always parent->child or
				 * that the child lock is not held when acquiring the parent lock.
				 */
				ao2_lock(child);
				instance = child;
				rtp = ast_rtp_instance_get_data(instance);
			} else {
				/* The child is the parent! We don't need to unlock it. */
				child = NULL;
				rtp = transport_rtp;
			}
		} else {
			child = NULL;
			rtp = transport_rtp;
		}

		if (ssrc_valid && rtp->themssrc_valid) {
			/*
			 * If the SSRC is 1, we still need to handle RTCP since this could be a
			 * special case. For example, if we have a unidirectional video stream, the
			 * SSRC may be set to 1 by the browser (in the case of chromium), and requests
			 * will still need to be processed so that video can flow as expected. This
			 * should only be done for PLI and FUR, since there is not a way to get the
			 * appropriate rtp instance when the SSRC is 1.
			 */
			int exception = (ssrc == 1 && !((pt == RTCP_PT_PSFB && rc == AST_RTP_RTCP_FMT_PLI) || pt == RTCP_PT_FUR));
			if ((ssrc != rtp->themssrc && use_packet_source && ssrc != 1)
					|| exception) {
				/*
				 * Skip over this RTCP record as it does not contain the
				 * correct SSRC.  We should not act upon RTCP records
				 * for a different stream.
				 */
				position += length;
				ast_debug(1, "%p -- RTCP from %s: Skipping record, received SSRC '%u' != expected '%u'\n",
					rtp, ast_sockaddr_stringify(addr), ssrc, rtp->themssrc);
				if (child) {
					ao2_unlock(child);
				}
				continue;
			}
			ssrc_seen = 1;
		}

		if (ssrc_seen && ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_NAT)) {
			/* Send to whoever sent to us */
			if (ast_sockaddr_cmp(&rtp->rtcp->them, addr)) {
				ast_sockaddr_copy(&rtp->rtcp->them, addr);
				if (rtpdebug) {
					ast_debug(0, "RTCP NAT: Got RTCP from other end. Now sending to address %s\n",
						ast_sockaddr_stringify(addr));
				}
			}
		}

		i += RTCP_HEADER_SSRC_LENGTH; /* Advance past header and ssrc */
		switch (pt) {
		case RTCP_PT_SR:
			gettimeofday(&rtp->rtcp->rxlsr, NULL);
			rtp->rtcp->themrxlsr = ((ntohl(rtcpheader[i]) & 0x0000ffff) << 16) | ((ntohl(rtcpheader[i + 1]) & 0xffff0000) >> 16);
			rtp->rtcp->spc = ntohl(rtcpheader[i + 3]);
			rtp->rtcp->soc = ntohl(rtcpheader[i + 4]);

			rtcp_report->type = RTCP_PT_SR;
			rtcp_report->sender_information.packet_count = rtp->rtcp->spc;
			rtcp_report->sender_information.octet_count = rtp->rtcp->soc;
			ntp2timeval((unsigned int)ntohl(rtcpheader[i]),
					(unsigned int)ntohl(rtcpheader[i + 1]),
					&rtcp_report->sender_information.ntp_timestamp);
			rtcp_report->sender_information.rtp_timestamp = ntohl(rtcpheader[i + 2]);
			if (rtcp_debug_test_addr(addr)) {
				ast_verbose("NTP timestamp: %u.%06u\n",
						(unsigned int)rtcp_report->sender_information.ntp_timestamp.tv_sec,
						(unsigned int)rtcp_report->sender_information.ntp_timestamp.tv_usec);
				ast_verbose("RTP timestamp: %u\n", rtcp_report->sender_information.rtp_timestamp);
				ast_verbose("SPC: %u\tSOC: %u\n",
						rtcp_report->sender_information.packet_count,
						rtcp_report->sender_information.octet_count);
			}
			i += RTCP_SR_BLOCK_WORD_LENGTH;
			/* Intentional fall through */
		case RTCP_PT_RR:
			if (rtcp_report->type != RTCP_PT_SR) {
				rtcp_report->type = RTCP_PT_RR;
			}

			if (rc > 0) {
				/* Don't handle multiple reception reports (rc > 1) yet */
				report_block = ast_calloc(1, sizeof(*report_block));
				if (!report_block) {
					if (child) {
						ao2_unlock(child);
					}
					return &ast_null_frame;
				}
				rtcp_report->report_block[0] = report_block;
				report_block->source_ssrc = ntohl(rtcpheader[i]);
				report_block->lost_count.packets = ntohl(rtcpheader[i + 1]) & 0x00ffffff;
				report_block->lost_count.fraction = ((ntohl(rtcpheader[i + 1]) & 0xff000000) >> 24);
				report_block->highest_seq_no = ntohl(rtcpheader[i + 2]);
				report_block->ia_jitter =  ntohl(rtcpheader[i + 3]);
				report_block->lsr = ntohl(rtcpheader[i + 4]);
				report_block->dlsr = ntohl(rtcpheader[i + 5]);
				if (report_block->lsr
					&& update_rtt_stats(rtp, report_block->lsr, report_block->dlsr)
					&& rtcp_debug_test_addr(addr)) {
					struct timeval now;
					unsigned int lsr_now, lsw, msw;
					gettimeofday(&now, NULL);
					timeval2ntp(now, &msw, &lsw);
					lsr_now = (((msw & 0xffff) << 16) | ((lsw & 0xffff0000) >> 16));
					ast_verbose("Internal RTCP NTP clock skew detected: "
							   "lsr=%u, now=%u, dlsr=%u (%u:%03ums), "
							"diff=%u\n",
							report_block->lsr, lsr_now, report_block->dlsr, report_block->dlsr / 65536,
							(report_block->dlsr % 65536) * 1000 / 65536,
							report_block->dlsr - (lsr_now - report_block->lsr));
				}
				update_jitter_stats(rtp, report_block->ia_jitter);
				update_lost_stats(rtp, report_block->lost_count.packets);
				rtp->rtcp->reported_jitter_count++;

				if (rtcp_debug_test_addr(addr)) {
					ast_verbose("  Fraction lost: %d\n", report_block->lost_count.fraction);
					ast_verbose("  Packets lost so far: %u\n", report_block->lost_count.packets);
					ast_verbose("  Highest sequence number: %u\n", report_block->highest_seq_no & 0x0000ffff);
					ast_verbose("  Sequence number cycles: %u\n", report_block->highest_seq_no >> 16);
					ast_verbose("  Interarrival jitter: %u\n", report_block->ia_jitter);
					ast_verbose("  Last SR(our NTP): %lu.%010lu\n",(unsigned long)(report_block->lsr) >> 16,((unsigned long)(report_block->lsr) << 16) * 4096);
					ast_verbose("  DLSR: %4.4f (sec)\n",(double)report_block->dlsr / 65536.0);
					ast_verbose("  RTT: %4.4f(sec)\n", rtp->rtcp->rtt);
				}
			}
			/* If and when we handle more than one report block, this should occur outside
			 * this loop.
			 */

			message_blob = ast_json_pack("{s: s, s: s, s: f}",
				"from", ast_sockaddr_stringify(addr),
				"to", transport_rtp->rtcp->local_addr_str,
				"rtt", rtp->rtcp->rtt);
			ast_rtp_publish_rtcp_message(instance, ast_rtp_rtcp_received_type(),
					rtcp_report,
					message_blob);
			ast_json_unref(message_blob);

			/* Return an AST_FRAME_RTCP frame with the ast_rtp_rtcp_report
			 * object as a its data */
			transport_rtp->f.frametype = AST_FRAME_RTCP;
			transport_rtp->f.subclass.integer = pt;
			transport_rtp->f.data.ptr = rtp->rtcp->frame_buf + AST_FRIENDLY_OFFSET;
			memcpy(transport_rtp->f.data.ptr, rtcp_report, sizeof(struct ast_rtp_rtcp_report));
			transport_rtp->f.datalen = sizeof(struct ast_rtp_rtcp_report);
			if (rc > 0) {
				/* There's always a single report block stored, here */
				struct ast_rtp_rtcp_report *rtcp_report2;
				report_block = transport_rtp->f.data.ptr + transport_rtp->f.datalen + sizeof(struct ast_rtp_rtcp_report_block *);
				memcpy(report_block, rtcp_report->report_block[0], sizeof(struct ast_rtp_rtcp_report_block));
				rtcp_report2 = (struct ast_rtp_rtcp_report *)transport_rtp->f.data.ptr;
				rtcp_report2->report_block[0] = report_block;
				transport_rtp->f.datalen += sizeof(struct ast_rtp_rtcp_report_block);
			}
			transport_rtp->f.offset = AST_FRIENDLY_OFFSET;
			transport_rtp->f.samples = 0;
			transport_rtp->f.mallocd = 0;
			transport_rtp->f.delivery.tv_sec = 0;
			transport_rtp->f.delivery.tv_usec = 0;
			transport_rtp->f.src = "RTP";
			f = &transport_rtp->f;
			break;
		case AST_RTP_RTCP_RTPFB:
			switch (rc) {
			case AST_RTP_RTCP_FMT_NACK:
				/* If retransmissions are not enabled ignore this message */
				if (!rtp->send_buffer) {
					break;
				}

				if (rtcp_debug_test_addr(addr)) {
					ast_verbose("Received generic RTCP NACK message\n");
				}

				ast_rtp_rtcp_handle_nack(instance, rtcpheader, position, length);
				break;
			default:
				break;
			}
			break;
		case RTCP_PT_FUR:
			/* Handle RTCP FUR as FIR by setting the format to 4 */
			rc = AST_RTP_RTCP_FMT_FIR;
		case RTCP_PT_PSFB:
			switch (rc) {
			case AST_RTP_RTCP_FMT_PLI:
			case AST_RTP_RTCP_FMT_FIR:
				if (rtcp_debug_test_addr(addr)) {
					ast_verbose("Received an RTCP Fast Update Request\n");
				}
				transport_rtp->f.frametype = AST_FRAME_CONTROL;
				transport_rtp->f.subclass.integer = AST_CONTROL_VIDUPDATE;
				transport_rtp->f.datalen = 0;
				transport_rtp->f.samples = 0;
				transport_rtp->f.mallocd = 0;
				transport_rtp->f.src = "RTP";
				f = &transport_rtp->f;
				break;
			case AST_RTP_RTCP_FMT_REMB:
				/* If REMB support is not enabled ignore this message */
				if (!ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_REMB)) {
					break;
				}

				if (rtcp_debug_test_addr(addr)) {
					ast_verbose("Received REMB report\n");
				}
				transport_rtp->f.frametype = AST_FRAME_RTCP;
				transport_rtp->f.subclass.integer = pt;
				transport_rtp->f.stream_num = rtp->stream_num;
				transport_rtp->f.data.ptr = rtp->rtcp->frame_buf + AST_FRIENDLY_OFFSET;
				feedback = transport_rtp->f.data.ptr;
				feedback->fmt = rc;

				/* We don't actually care about the SSRC information in the feedback message */
				first_word = ntohl(rtcpheader[i + 2]);
				feedback->remb.br_exp = (first_word >> 18) & ((1 << 6) - 1);
				feedback->remb.br_mantissa = first_word & ((1 << 18) - 1);

				transport_rtp->f.datalen = sizeof(struct ast_rtp_rtcp_feedback);
				transport_rtp->f.offset = AST_FRIENDLY_OFFSET;
				transport_rtp->f.samples = 0;
				transport_rtp->f.mallocd = 0;
				transport_rtp->f.delivery.tv_sec = 0;
				transport_rtp->f.delivery.tv_usec = 0;
				transport_rtp->f.src = "RTP";
				f = &transport_rtp->f;
				break;
			default:
				break;
			}
			break;
		case RTCP_PT_SDES:
			if (rtcp_debug_test_addr(addr)) {
				ast_verbose("Received an SDES from %s\n",
					ast_sockaddr_stringify(addr));
			}
			break;
		case RTCP_PT_BYE:
			if (rtcp_debug_test_addr(addr)) {
				ast_verbose("Received a BYE from %s\n",
					ast_sockaddr_stringify(addr));
			}
			break;
		default:
			break;
		}
		position += length;
		rtp->rtcp->rtcp_info = 1;

		if (child) {
			ao2_unlock(child);
		}
	}

	return f;
}

/*! \pre instance is locked */
static struct ast_frame *ast_rtcp_read(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_srtp *srtp = ast_rtp_instance_get_srtp(instance, 1);
	struct ast_sockaddr addr;
	unsigned char rtcpdata[8192 + AST_FRIENDLY_OFFSET];
	unsigned char *read_area = rtcpdata + AST_FRIENDLY_OFFSET;
	size_t read_area_size = sizeof(rtcpdata) - AST_FRIENDLY_OFFSET;
	int res;

	/* Read in RTCP data from the socket */
	if ((res = rtcp_recvfrom(instance, read_area, read_area_size,
				0, &addr)) < 0) {
		if (res == RTP_DTLS_ESTABLISHED) {
			rtp->f.frametype = AST_FRAME_CONTROL;
			rtp->f.subclass.integer = AST_CONTROL_SRCCHANGE;
			return &rtp->f;
		}

		ast_assert(errno != EBADF);
		if (errno != EAGAIN) {
			ast_log(LOG_WARNING, "RTCP Read error: %s.  Hanging up.\n",
				(errno) ? strerror(errno) : "Unspecified");
			return NULL;
		}
		return &ast_null_frame;
	}

	/* If this was handled by the ICE session don't do anything further */
	if (!res) {
		return &ast_null_frame;
	}

	if (!*read_area) {
		struct sockaddr_in addr_tmp;
		struct ast_sockaddr addr_v4;

		if (ast_sockaddr_is_ipv4(&addr)) {
			ast_sockaddr_to_sin(&addr, &addr_tmp);
		} else if (ast_sockaddr_ipv4_mapped(&addr, &addr_v4)) {
			ast_debug(1, "Using IPv6 mapped address %s for STUN\n",
				  ast_sockaddr_stringify(&addr));
			ast_sockaddr_to_sin(&addr_v4, &addr_tmp);
		} else {
			ast_debug(1, "Cannot do STUN for non IPv4 address %s\n",
				  ast_sockaddr_stringify(&addr));
			return &ast_null_frame;
		}
		if ((ast_stun_handle_packet(rtp->rtcp->s, &addr_tmp, read_area, res, NULL, NULL) == AST_STUN_ACCEPT)) {
			ast_sockaddr_from_sin(&addr, &addr_tmp);
			ast_sockaddr_copy(&rtp->rtcp->them, &addr);
		}
		return &ast_null_frame;
	}

	return ast_rtcp_interpret(instance, srtp, read_area, res, &addr);
}

/*! \pre instance is locked */
static int bridge_p2p_rtp_write(struct ast_rtp_instance *instance,
	struct ast_rtp_instance *instance1, unsigned int *rtpheader, int len, int hdrlen)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_rtp *bridged;
	int res = 0, payload = 0, bridged_payload = 0, mark;
	RAII_VAR(struct ast_rtp_payload_type *, payload_type, NULL, ao2_cleanup);
	int reconstruct = ntohl(rtpheader[0]);
	struct ast_sockaddr remote_address = { {0,} };
	int ice;
	unsigned int timestamp = ntohl(rtpheader[1]);

	/* Get fields from packet */
	payload = (reconstruct & 0x7f0000) >> 16;
	mark = (reconstruct & 0x800000) >> 23;

	/* Check what the payload value should be */
	payload_type = ast_rtp_codecs_get_payload(ast_rtp_instance_get_codecs(instance), payload);
	if (!payload_type) {
		return -1;
	}

	/* Otherwise adjust bridged payload to match */
	bridged_payload = ast_rtp_codecs_payload_code_tx(ast_rtp_instance_get_codecs(instance1),
		payload_type->asterisk_format, payload_type->format, payload_type->rtp_code);

	/* If no codec could be matched between instance and instance1, then somehow things were made incompatible while we were still bridged.  Bail. */
	if (bridged_payload < 0) {
		return -1;
	}

	/* If the payload coming in is not one of the negotiated ones then send it to the core, this will cause formats to change and the bridge to break */
	if (ast_rtp_codecs_find_payload_code(ast_rtp_instance_get_codecs(instance1), bridged_payload) == -1) {
		ast_debug(1, "Unsupported payload type received \n");
		return -1;
	}

	/*
	 * Even if we are no longer in dtmf, we could still be receiving
	 * re-transmissions of the last dtmf end still.  Feed those to the
	 * core so they can be filtered accordingly.
	 */
	if (rtp->last_end_timestamp == timestamp) {
		ast_debug(1, "Feeding packet with duplicate timestamp to core\n");
		return -1;
	}

	if (payload_type->asterisk_format) {
		ao2_replace(rtp->lastrxformat, payload_type->format);
	}

	/*
	 * We have now determined that we need to send the RTP packet
	 * out the bridged instance to do local bridging so we must unlock
	 * the receiving instance to prevent deadlock with the bridged
	 * instance.
	 *
	 * Technically we should grab a ref to instance1 so it won't go
	 * away on us.  However, we should be safe because the bridged
	 * instance won't change without both channels involved being
	 * locked and we currently have the channel lock for the receiving
	 * instance.
	 */
	ao2_unlock(instance);
	ao2_lock(instance1);

	/*
	 * Get the peer rtp pointer now to emphasize that using it
	 * must happen while instance1 is locked.
	 */
	bridged = ast_rtp_instance_get_data(instance1);


	/* If bridged peer is in dtmf, feed all packets to core until it finishes to avoid infinite dtmf */
	if (bridged->sending_digit) {
		ast_debug(1, "Feeding packet to core until DTMF finishes\n");
		ao2_unlock(instance1);
		ao2_lock(instance);
		return -1;
	}

	if (payload_type->asterisk_format) {
		/*
		 * If bridged peer has already received rtp, perform the asymmetric codec check
		 * if that feature has been activated
		 */
		if (!bridged->asymmetric_codec
			&& bridged->lastrxformat != ast_format_none
			&& ast_format_cmp(payload_type->format, bridged->lastrxformat) == AST_FORMAT_CMP_NOT_EQUAL) {
			ast_debug(1, "Asymmetric RTP codecs detected (TX: %s, RX: %s) sending frame to core\n",
				ast_format_get_name(payload_type->format),
				ast_format_get_name(bridged->lastrxformat));
			ao2_unlock(instance1);
			ao2_lock(instance);
			return -1;
		}

		ao2_replace(bridged->lasttxformat, payload_type->format);
	}

	ast_rtp_instance_get_remote_address(instance1, &remote_address);

	if (ast_sockaddr_isnull(&remote_address)) {
		ast_debug(5, "Remote address is null, most likely RTP has been stopped\n");
		ao2_unlock(instance1);
		ao2_lock(instance);
		return 0;
	}

	/* If the marker bit has been explicitly set turn it on */
	if (ast_test_flag(bridged, FLAG_NEED_MARKER_BIT)) {
		mark = 1;
		ast_clear_flag(bridged, FLAG_NEED_MARKER_BIT);
	}

	/* Set the marker bit for the first local bridged packet which has the first bridged peer's SSRC. */
	if (ast_test_flag(bridged, FLAG_REQ_LOCAL_BRIDGE_BIT)) {
		mark = 1;
		ast_clear_flag(bridged, FLAG_REQ_LOCAL_BRIDGE_BIT);
	}

	/* Reconstruct part of the packet */
	reconstruct &= 0xFF80FFFF;
	reconstruct |= (bridged_payload << 16);
	reconstruct |= (mark << 23);
	rtpheader[0] = htonl(reconstruct);

	/* Send the packet back out */
	res = rtp_sendto(instance1, (void *)rtpheader, len, 0, &remote_address, &ice);
	if (res < 0) {
		if (!ast_rtp_instance_get_prop(instance1, AST_RTP_PROPERTY_NAT) || (ast_rtp_instance_get_prop(instance1, AST_RTP_PROPERTY_NAT) && (ast_test_flag(bridged, FLAG_NAT_ACTIVE) == FLAG_NAT_ACTIVE))) {
			ast_log(LOG_WARNING,
				"RTP Transmission error of packet to %s: %s\n",
				ast_sockaddr_stringify(&remote_address),
				strerror(errno));
		} else if (((ast_test_flag(bridged, FLAG_NAT_ACTIVE) == FLAG_NAT_INACTIVE) || rtpdebug) && !ast_test_flag(bridged, FLAG_NAT_INACTIVE_NOWARN)) {
			if (rtpdebug || DEBUG_ATLEAST(1)) {
				ast_log(LOG_WARNING,
					"RTP NAT: Can't write RTP to private "
					"address %s, waiting for other end to "
					"send audio...\n",
					ast_sockaddr_stringify(&remote_address));
			}
			ast_set_flag(bridged, FLAG_NAT_INACTIVE_NOWARN);
		}
		ao2_unlock(instance1);
		ao2_lock(instance);
		return 0;
	}

	if (rtp_debug_test_addr(&remote_address)) {
		ast_verbose("Sent RTP P2P packet to %s%s (type %-2.2d, len %-6.6d)\n",
			    ast_sockaddr_stringify(&remote_address),
			    ice ? " (via ICE)" : "",
			    bridged_payload, len - hdrlen);
	}

	ao2_unlock(instance1);
	ao2_lock(instance);
	return 0;
}

static void rtp_instance_unlock(struct ast_rtp_instance *instance)
{
	if (instance) {
		ao2_unlock(instance);
	}
}

static struct ast_frame *ast_rtp_interpret(struct ast_rtp_instance *instance, struct ast_srtp *srtp,
	const struct ast_sockaddr *remote_address, unsigned char *read_area, int length, int prev_seqno)
{
	unsigned int *rtpheader = (unsigned int*)(read_area);
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_rtp_instance *instance1;
	int res = length, hdrlen = 12, seqno, timestamp, payloadtype, padding, mark, ext, cc;
	RAII_VAR(struct ast_rtp_payload_type *, payload, NULL, ao2_cleanup);
	struct frame_list frames;

	/* If this payload is encrypted then decrypt it using the given SRTP instance */
	if ((*read_area & 0xC0) && res_srtp && srtp && res_srtp->unprotect(
		    srtp, read_area, &res, 0) < 0) {
		return &ast_null_frame;
	}

	/* If we are currently sending DTMF to the remote party send a continuation packet */
	if (rtp->sending_digit) {
		ast_rtp_dtmf_continuation(instance);
	}

	/* Pull out the various other fields we will need */
	seqno = ntohl(rtpheader[0]);
	payloadtype = (seqno & 0x7f0000) >> 16;
	padding = seqno & (1 << 29);
	mark = seqno & (1 << 23);
	ext = seqno & (1 << 28);
	cc = (seqno & 0xF000000) >> 24;
	seqno &= 0xffff;
	timestamp = ntohl(rtpheader[1]);

	AST_LIST_HEAD_INIT_NOLOCK(&frames);

	/* Remove any padding bytes that may be present */
	if (padding) {
		res -= read_area[res - 1];
	}

	/* Skip over any CSRC fields */
	if (cc) {
		hdrlen += cc * 4;
	}

	/* Look for any RTP extensions, currently we do not support any */
	if (ext) {
		hdrlen += (ntohl(rtpheader[hdrlen/4]) & 0xffff) << 2;
		hdrlen += 4;
		if (DEBUG_ATLEAST(1)) {
			unsigned int profile;
			profile = (ntohl(rtpheader[3]) & 0xffff0000) >> 16;
			if (profile == 0x505a) {
				ast_log(LOG_DEBUG, "Found Zfone extension in RTP stream - zrtp - not supported.\n");
			} else if (profile != 0xbede) {
				/* SDP negotiated RTP extensions can not currently be output in logging */
				ast_log(LOG_DEBUG, "Found unknown RTP Extensions %x\n", profile);
			}
		}
	}

	/* Make sure after we potentially mucked with the header length that it is once again valid */
	if (res < hdrlen) {
		ast_log(LOG_WARNING, "RTP Read too short (%d, expecting %d\n", res, hdrlen);
		return AST_LIST_FIRST(&frames) ? AST_LIST_FIRST(&frames) : &ast_null_frame;
	}

	rtp->rxcount++;
	rtp->rxoctetcount += (res - hdrlen);
	if (rtp->rxcount == 1) {
		rtp->seedrxseqno = seqno;
	}

	/* Do not schedule RR if RTCP isn't run */
	if (rtp->rtcp && !ast_sockaddr_isnull(&rtp->rtcp->them) && rtp->rtcp->schedid < 0) {
		/* Schedule transmission of Receiver Report */
		ao2_ref(instance, +1);
		rtp->rtcp->schedid = ast_sched_add(rtp->sched, ast_rtcp_calc_interval(rtp), ast_rtcp_write, instance);
		if (rtp->rtcp->schedid < 0) {
			ao2_ref(instance, -1);
			ast_log(LOG_WARNING, "scheduling RTCP transmission failed.\n");
		}
	}
	if ((int)rtp->lastrxseqno - (int)seqno  > 100) /* if so it would indicate that the sender cycled; allow for misordering */
		rtp->cycles += RTP_SEQ_MOD;

	/* If we are directly bridged to another instance send the audio directly out,
	 * but only after updating core information about the received traffic so that
	 * outgoing RTCP reflects it.
	 */
	instance1 = ast_rtp_instance_get_bridged(instance);
	if (instance1
		&& !bridge_p2p_rtp_write(instance, instance1, rtpheader, res, hdrlen)) {
		struct timeval rxtime;
		struct ast_frame *f;

		/* Update statistics for jitter so they are correct in RTCP */
		calc_rxstamp(&rxtime, rtp, timestamp, mark);

		/* When doing P2P we don't need to raise any frames about SSRC change to the core */
		while ((f = AST_LIST_REMOVE_HEAD(&frames, frame_list)) != NULL) {
			ast_frfree(f);
		}

		return &ast_null_frame;
	}

	payload = ast_rtp_codecs_get_payload(ast_rtp_instance_get_codecs(instance), payloadtype);
	if (!payload) {
		/* Unknown payload type. */
		return AST_LIST_FIRST(&frames) ? AST_LIST_FIRST(&frames) : &ast_null_frame;
	}

	/* If the payload is not actually an Asterisk one but a special one pass it off to the respective handler */
	if (!payload->asterisk_format) {
		struct ast_frame *f = NULL;
		if (payload->rtp_code == AST_RTP_DTMF) {
			/* process_dtmf_rfc2833 may need to return multiple frames. We do this
			 * by passing the pointer to the frame list to it so that the method
			 * can append frames to the list as needed.
			 */
			process_dtmf_rfc2833(instance, read_area + hdrlen, res - hdrlen, seqno, timestamp, payloadtype, mark, &frames);
		} else if (payload->rtp_code == AST_RTP_CISCO_DTMF) {
			f = process_dtmf_cisco(instance, read_area + hdrlen, res - hdrlen, seqno, timestamp, payloadtype, mark);
		} else if (payload->rtp_code == AST_RTP_CN) {
			f = process_cn_rfc3389(instance, read_area + hdrlen, res - hdrlen, seqno, timestamp, payloadtype, mark);
		} else {
			ast_log(LOG_NOTICE, "Unknown RTP codec %d received from '%s'\n",
				payloadtype,
				ast_sockaddr_stringify(remote_address));
		}

		if (f) {
			AST_LIST_INSERT_TAIL(&frames, f, frame_list);
		}
		/* Even if no frame was returned by one of the above methods,
		 * we may have a frame to return in our frame list
		 */
		return AST_LIST_FIRST(&frames) ? AST_LIST_FIRST(&frames) : &ast_null_frame;
	}

	ao2_replace(rtp->lastrxformat, payload->format);
	ao2_replace(rtp->f.subclass.format, payload->format);
	switch (ast_format_get_type(rtp->f.subclass.format)) {
	case AST_MEDIA_TYPE_AUDIO:
		rtp->f.frametype = AST_FRAME_VOICE;
		break;
	case AST_MEDIA_TYPE_VIDEO:
		rtp->f.frametype = AST_FRAME_VIDEO;
		break;
	case AST_MEDIA_TYPE_TEXT:
		rtp->f.frametype = AST_FRAME_TEXT;
		break;
	case AST_MEDIA_TYPE_IMAGE:
		/* Fall through */
	default:
		ast_log(LOG_WARNING, "Unknown or unsupported media type: %s\n",
			ast_codec_media_type2str(ast_format_get_type(rtp->f.subclass.format)));
		return &ast_null_frame;
	}

	if (rtp->dtmf_timeout && rtp->dtmf_timeout < timestamp) {
		rtp->dtmf_timeout = 0;

		if (rtp->resp) {
			struct ast_frame *f;
			f = create_dtmf_frame(instance, AST_FRAME_DTMF_END, 0);
			f->len = ast_tvdiff_ms(ast_samp2tv(rtp->dtmf_duration, rtp_get_rate(f->subclass.format)), ast_tv(0, 0));
			rtp->resp = 0;
			rtp->dtmf_timeout = rtp->dtmf_duration = 0;
			AST_LIST_INSERT_TAIL(&frames, f, frame_list);
			return AST_LIST_FIRST(&frames);
		}
	}

	rtp->f.src = "RTP";
	rtp->f.mallocd = 0;
	rtp->f.datalen = res - hdrlen;
	rtp->f.data.ptr = read_area + hdrlen;
	rtp->f.offset = hdrlen + AST_FRIENDLY_OFFSET;
	ast_set_flag(&rtp->f, AST_FRFLAG_HAS_SEQUENCE_NUMBER);
	rtp->f.seqno = seqno;
	rtp->f.stream_num = rtp->stream_num;

	if ((ast_format_cmp(rtp->f.subclass.format, ast_format_t140) == AST_FORMAT_CMP_EQUAL)
		&& ((int)seqno - (prev_seqno + 1) > 0)
		&& ((int)seqno - (prev_seqno + 1) < 10)) {
		unsigned char *data = rtp->f.data.ptr;

		memmove(rtp->f.data.ptr+3, rtp->f.data.ptr, rtp->f.datalen);
		rtp->f.datalen +=3;
		*data++ = 0xEF;
		*data++ = 0xBF;
		*data = 0xBD;
	}

	if (ast_format_cmp(rtp->f.subclass.format, ast_format_t140_red) == AST_FORMAT_CMP_EQUAL) {
		unsigned char *data = rtp->f.data.ptr;
		unsigned char *header_end;
		int num_generations;
		int header_length;
		int len;
		int diff =(int)seqno - (prev_seqno+1); /* if diff = 0, no drop*/
		int x;

		ao2_replace(rtp->f.subclass.format, ast_format_t140);
		header_end = memchr(data, ((*data) & 0x7f), rtp->f.datalen);
		if (header_end == NULL) {
			return AST_LIST_FIRST(&frames) ? AST_LIST_FIRST(&frames) : &ast_null_frame;
		}
		header_end++;

		header_length = header_end - data;
		num_generations = header_length / 4;
		len = header_length;

		if (!diff) {
			for (x = 0; x < num_generations; x++)
				len += data[x * 4 + 3];

			if (!(rtp->f.datalen - len))
				return AST_LIST_FIRST(&frames) ? AST_LIST_FIRST(&frames) : &ast_null_frame;

			rtp->f.data.ptr += len;
			rtp->f.datalen -= len;
		} else if (diff > num_generations && diff < 10) {
			len -= 3;
			rtp->f.data.ptr += len;
			rtp->f.datalen -= len;

			data = rtp->f.data.ptr;
			*data++ = 0xEF;
			*data++ = 0xBF;
			*data = 0xBD;
		} else {
			for ( x = 0; x < num_generations - diff; x++)
				len += data[x * 4 + 3];

			rtp->f.data.ptr += len;
			rtp->f.datalen -= len;
		}
	}

	if (ast_format_get_type(rtp->f.subclass.format) == AST_MEDIA_TYPE_AUDIO) {
		rtp->f.samples = ast_codec_samples_count(&rtp->f);
		if (ast_format_cache_is_slinear(rtp->f.subclass.format)) {
			ast_frame_byteswap_be(&rtp->f);
		}
		calc_rxstamp(&rtp->f.delivery, rtp, timestamp, mark);
		/* Add timing data to let ast_generic_bridge() put the frame into a jitterbuf */
		ast_set_flag(&rtp->f, AST_FRFLAG_HAS_TIMING_INFO);
		rtp->f.ts = timestamp / (rtp_get_rate(rtp->f.subclass.format) / 1000);
		rtp->f.len = rtp->f.samples / ((ast_format_get_sample_rate(rtp->f.subclass.format) / 1000));
	} else if (ast_format_get_type(rtp->f.subclass.format) == AST_MEDIA_TYPE_VIDEO) {
		/* Video -- samples is # of samples vs. 90000 */
		if (!rtp->lastividtimestamp)
			rtp->lastividtimestamp = timestamp;
		ast_set_flag(&rtp->f, AST_FRFLAG_HAS_TIMING_INFO);
		rtp->f.ts = timestamp / (rtp_get_rate(rtp->f.subclass.format) / 1000);
		rtp->f.samples = timestamp - rtp->lastividtimestamp;
		rtp->lastividtimestamp = timestamp;
		rtp->f.delivery.tv_sec = 0;
		rtp->f.delivery.tv_usec = 0;
		/* Pass the RTP marker bit as bit */
		rtp->f.subclass.frame_ending = mark ? 1 : 0;
	} else if (ast_format_get_type(rtp->f.subclass.format) == AST_MEDIA_TYPE_TEXT) {
		/* TEXT -- samples is # of samples vs. 1000 */
		if (!rtp->lastitexttimestamp)
			rtp->lastitexttimestamp = timestamp;
		rtp->f.samples = timestamp - rtp->lastitexttimestamp;
		rtp->lastitexttimestamp = timestamp;
		rtp->f.delivery.tv_sec = 0;
		rtp->f.delivery.tv_usec = 0;
	} else {
		ast_log(LOG_WARNING, "Unknown or unsupported media type: %s\n",
			ast_codec_media_type2str(ast_format_get_type(rtp->f.subclass.format)));
		return &ast_null_frame;
	}

	AST_LIST_INSERT_TAIL(&frames, &rtp->f, frame_list);
	return AST_LIST_FIRST(&frames);
}

/*! \pre instance is locked */
static struct ast_frame *ast_rtp_read(struct ast_rtp_instance *instance, int rtcp)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_srtp *srtp;
	RAII_VAR(struct ast_rtp_instance *, child, NULL, rtp_instance_unlock);
	struct ast_sockaddr addr;
	int res, hdrlen = 12, version, payloadtype, mark;
	unsigned char *read_area = rtp->rawdata + AST_FRIENDLY_OFFSET;
	size_t read_area_size = sizeof(rtp->rawdata) - AST_FRIENDLY_OFFSET;
	unsigned int *rtpheader = (unsigned int*)(read_area), seqno, ssrc, timestamp, prev_seqno;
	struct ast_sockaddr remote_address = { {0,} };
	struct frame_list frames;
	struct ast_frame *frame;

	/* If this is actually RTCP let's hop on over and handle it */
	if (rtcp) {
		if (rtp->rtcp && rtp->rtcp->type == AST_RTP_INSTANCE_RTCP_STANDARD) {
			return ast_rtcp_read(instance);
		}
		return &ast_null_frame;
	}

	/* Actually read in the data from the socket */
	if ((res = rtp_recvfrom(instance, read_area, read_area_size, 0,
				&addr)) < 0) {
		if (res == RTP_DTLS_ESTABLISHED) {
			rtp->f.frametype = AST_FRAME_CONTROL;
			rtp->f.subclass.integer = AST_CONTROL_SRCCHANGE;
			return &rtp->f;
		}

		ast_assert(errno != EBADF);
		if (errno != EAGAIN) {
			ast_log(LOG_WARNING, "RTP Read error: %s.  Hanging up.\n",
				(errno) ? strerror(errno) : "Unspecified");
			return NULL;
		}
		return &ast_null_frame;
	}

	/* If this was handled by the ICE session don't do anything */
	if (!res) {
		return &ast_null_frame;
	}

	/* This could be a multiplexed RTCP packet. If so, be sure to interpret it correctly */
	if (rtcp_mux(rtp, read_area)) {
		return ast_rtcp_interpret(instance, ast_rtp_instance_get_srtp(instance, 1), read_area, res, &addr);
	}

	/* Make sure the data that was read in is actually enough to make up an RTP packet */
	if (res < hdrlen) {
		/* If this is a keepalive containing only nulls, don't bother with a warning */
		int i;
		for (i = 0; i < res; ++i) {
			if (read_area[i] != '\0') {
				ast_log(LOG_WARNING, "RTP Read too short\n");
				return &ast_null_frame;
			}
		}
		return &ast_null_frame;
	}

	/* Get fields and verify this is an RTP packet */
	seqno = ntohl(rtpheader[0]);

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	if (!(version = (seqno & 0xC0000000) >> 30)) {
		struct sockaddr_in addr_tmp;
		struct ast_sockaddr addr_v4;
		if (ast_sockaddr_is_ipv4(&addr)) {
			ast_sockaddr_to_sin(&addr, &addr_tmp);
		} else if (ast_sockaddr_ipv4_mapped(&addr, &addr_v4)) {
			ast_debug(1, "Using IPv6 mapped address %s for STUN\n",
				  ast_sockaddr_stringify(&addr));
			ast_sockaddr_to_sin(&addr_v4, &addr_tmp);
		} else {
			ast_debug(1, "Cannot do STUN for non IPv4 address %s\n",
				  ast_sockaddr_stringify(&addr));
			return &ast_null_frame;
		}
		if ((ast_stun_handle_packet(rtp->s, &addr_tmp, read_area, res, NULL, NULL) == AST_STUN_ACCEPT) &&
		    ast_sockaddr_isnull(&remote_address)) {
			ast_sockaddr_from_sin(&addr, &addr_tmp);
			ast_rtp_instance_set_remote_address(instance, &addr);
		}
		return &ast_null_frame;
	}

	/* If the version is not what we expected by this point then just drop the packet */
	if (version != 2) {
		return &ast_null_frame;
	}

	/* We use the SSRC to determine what RTP instance this packet is actually for */
	ssrc = ntohl(rtpheader[2]);

	/* We use the SRTP data from the provided instance that it came in on, not the child */
	srtp = ast_rtp_instance_get_srtp(instance, 0);

	/* Determine the appropriate instance for this */
	child = rtp_find_instance_by_packet_source_ssrc(instance, rtp, ssrc);
	if (!child) {
		/* Neither the bundled parent nor any child has this SSRC */
		return &ast_null_frame;
	}
	if (child != instance) {
		/* It is safe to hold the child lock while holding the parent lock, we guarantee that the locking order
		 * is always parent->child or that the child lock is not held when acquiring the parent lock.
		 */
		ao2_lock(child);
		instance = child;
		rtp = ast_rtp_instance_get_data(instance);
	} else {
		/* The child is the parent! We don't need to unlock it. */
		child = NULL;
	}

	/* If strict RTP protection is enabled see if we need to learn the remote address or if we need to drop the packet */
	switch (rtp->strict_rtp_state) {
	case STRICT_RTP_LEARN:
		/*
		 * Scenario setup:
		 * PartyA -- Ast1 -- Ast2 -- PartyB
		 *
		 * The learning timeout is necessary for Ast1 to handle the above
		 * setup where PartyA calls PartyB and Ast2 initiates direct media
		 * between Ast1 and PartyB.  Ast1 may lock onto the Ast2 stream and
		 * never learn the PartyB stream when it starts.  The timeout makes
		 * Ast1 stay in the learning state long enough to see and learn the
		 * RTP stream from PartyB.
		 *
		 * To mitigate against attack, the learning state cannot switch
		 * streams while there are competing streams.  The competing streams
		 * interfere with each other's qualification.  Once we accept a
		 * stream and reach the timeout, an attacker cannot interfere
		 * anymore.
		 *
		 * Here are a few scenarios and each one assumes that the streams
		 * are continuous:
		 *
		 * 1) We already have a known stream source address and the known
		 * stream wants to change to a new source address.  An attacking
		 * stream will block learning the new stream source.  After the
		 * timeout we re-lock onto the original stream source address which
		 * likely went away.  The result is one way audio.
		 *
		 * 2) We already have a known stream source address and the known
		 * stream doesn't want to change source addresses.  An attacking
		 * stream will not be able to replace the known stream.  After the
		 * timeout we re-lock onto the known stream.  The call is not
		 * affected.
		 *
		 * 3) We don't have a known stream source address.  This presumably
		 * is the start of a call.  Competing streams will result in staying
		 * in learning mode until a stream becomes the victor and we reach
		 * the timeout.  We cannot exit learning if we have no known stream
		 * to lock onto.  The result is one way audio until there is a victor.
		 *
		 * If we learn a stream source address before the timeout we will be
		 * in scenario 1) or 2) when a competing stream starts.
		 */
		if (!ast_sockaddr_isnull(&rtp->strict_rtp_address)
			&& STRICT_RTP_LEARN_TIMEOUT < ast_tvdiff_ms(ast_tvnow(), rtp->rtp_source_learn.start)) {
			ast_verb(4, "%p -- Strict RTP learning complete - Locking on source address %s\n",
				rtp, ast_sockaddr_stringify(&rtp->strict_rtp_address));
			ast_test_suite_event_notify("STRICT_RTP_LEARN", "Source: %s",
				ast_sockaddr_stringify(&rtp->strict_rtp_address));
			rtp->strict_rtp_state = STRICT_RTP_CLOSED;
		} else {
			struct ast_sockaddr target_address;

			if (!ast_sockaddr_cmp(&rtp->strict_rtp_address, &addr)) {
				/*
				 * We are open to learning a new address but have received
				 * traffic from the current address, accept it and reset
				 * the learning counts for a new source.  When no more
				 * current source packets arrive a new source can take over
				 * once sufficient traffic is received.
				 */
				rtp_learning_seq_init(&rtp->rtp_source_learn, seqno);
				break;
			}

			/*
			 * We give preferential treatment to the requested target address
			 * (negotiated SDP address) where we are to send our RTP.  However,
			 * the other end has no obligation to send from that address even
			 * though it is practically a requirement when NAT is involved.
			 */
			ast_rtp_instance_get_requested_target_address(instance, &target_address);
			if (!ast_sockaddr_cmp(&target_address, &addr)) {
				/* Accept the negotiated target RTP stream as the source */
				ast_verb(4, "%p -- Strict RTP switching to RTP target address %s as source\n",
					rtp, ast_sockaddr_stringify(&addr));
				ast_sockaddr_copy(&rtp->strict_rtp_address, &addr);
				rtp_learning_seq_init(&rtp->rtp_source_learn, seqno);
				break;
			}

			/*
			 * Trying to learn a new address.  If we pass a probationary period
			 * with it, that means we've stopped getting RTP from the original
			 * source and we should switch to it.
			 */
			if (!ast_sockaddr_cmp(&rtp->rtp_source_learn.proposed_address, &addr)) {
				if (rtp->rtp_source_learn.stream_type == AST_MEDIA_TYPE_UNKNOWN) {
					struct ast_rtp_codecs *codecs;

					codecs = ast_rtp_instance_get_codecs(instance);
					rtp->rtp_source_learn.stream_type =
						ast_rtp_codecs_get_stream_type(codecs);
					ast_verb(4, "%p -- Strict RTP qualifying stream type: %s\n",
						rtp, ast_codec_media_type2str(rtp->rtp_source_learn.stream_type));
				}
				if (!rtp_learning_rtp_seq_update(&rtp->rtp_source_learn, seqno)) {
					/* Accept the new RTP stream */
					ast_verb(4, "%p -- Strict RTP switching source address to %s\n",
						rtp, ast_sockaddr_stringify(&addr));
					ast_sockaddr_copy(&rtp->strict_rtp_address, &addr);
					rtp_learning_seq_init(&rtp->rtp_source_learn, seqno);
					break;
				}
				/* Not ready to accept the RTP stream candidate */
				ast_debug(1, "%p -- Received RTP packet from %s, dropping due to strict RTP protection. Will switch to it in %d packets.\n",
					rtp, ast_sockaddr_stringify(&addr), rtp->rtp_source_learn.packets);
			} else {
				/*
				 * This is either an attacking stream or
				 * the start of the expected new stream.
				 */
				ast_sockaddr_copy(&rtp->rtp_source_learn.proposed_address, &addr);
				rtp_learning_seq_init(&rtp->rtp_source_learn, seqno);
				ast_debug(1, "%p -- Received RTP packet from %s, dropping due to strict RTP protection. Qualifying new stream.\n",
					rtp, ast_sockaddr_stringify(&addr));
			}
			return &ast_null_frame;
		}
		/* Fall through */
	case STRICT_RTP_CLOSED:
		/*
		 * We should not allow a stream address change if the SSRC matches
		 * once strictrtp learning is closed.  Any kind of address change
		 * like this should have happened while we were in the learning
		 * state.  We do not want to allow the possibility of an attacker
		 * interfering with the RTP stream after the learning period.
		 * An attacker could manage to get an RTCP packet redirected to
		 * them which can contain the SSRC value.
		 */
		if (!ast_sockaddr_cmp(&rtp->strict_rtp_address, &addr)) {
			break;
		}
		ast_debug(1, "%p -- Received RTP packet from %s, dropping due to strict RTP protection.\n",
			rtp, ast_sockaddr_stringify(&addr));
#ifdef TEST_FRAMEWORK
	{
		static int strict_rtp_test_event = 1;
		if (strict_rtp_test_event) {
			ast_test_suite_event_notify("STRICT_RTP_CLOSED", "Source: %s",
				ast_sockaddr_stringify(&addr));
			strict_rtp_test_event = 0; /* Only run this event once to prevent possible spam */
		}
	}
#endif
		return &ast_null_frame;
	case STRICT_RTP_OPEN:
		break;
	}

	/* If symmetric RTP is enabled see if the remote side is not what we expected and change where we are sending audio */
	if (ast_rtp_instance_get_prop(instance, AST_RTP_PROPERTY_NAT)) {
		if (ast_sockaddr_cmp(&remote_address, &addr)) {
			/* do not update the originally given address, but only the remote */
			ast_rtp_instance_set_incoming_source_address(instance, &addr);
			ast_sockaddr_copy(&remote_address, &addr);
			if (rtp->rtcp && rtp->rtcp->type == AST_RTP_INSTANCE_RTCP_STANDARD) {
				ast_sockaddr_copy(&rtp->rtcp->them, &addr);
				ast_sockaddr_set_port(&rtp->rtcp->them, ast_sockaddr_port(&addr) + 1);
			}
			ast_set_flag(rtp, FLAG_NAT_ACTIVE);
			if (rtpdebug)
				ast_debug(0, "RTP NAT: Got audio from other end. Now sending to address %s\n",
					  ast_sockaddr_stringify(&remote_address));
		}
	}

	/* Pull out the various other fields we will need */
	payloadtype = (seqno & 0x7f0000) >> 16;
	mark = seqno & (1 << 23);
	seqno &= 0xffff;
	timestamp = ntohl(rtpheader[1]);

	if (rtp_debug_test_addr(&addr)) {
		ast_verbose("Got  RTP packet from    %s (type %-2.2d, seq %-6.6u, ts %-6.6u, len %-6.6d)\n",
			    ast_sockaddr_stringify(&addr),
			    payloadtype, seqno, timestamp, res - hdrlen);
	}

	AST_LIST_HEAD_INIT_NOLOCK(&frames);

	/* Only non-bundled instances can change/learn the remote's SSRC implicitly. */
	if (!child && !AST_VECTOR_SIZE(&rtp->ssrc_mapping)) {
		/* Force a marker bit and change SSRC if the SSRC changes */
		if (rtp->themssrc_valid && rtp->themssrc != ssrc) {
			struct ast_frame *f, srcupdate = {
				AST_FRAME_CONTROL,
				.subclass.integer = AST_CONTROL_SRCCHANGE,
			};

			if (!mark) {
				if (rtpdebug) {
					ast_debug(1, "Forcing Marker bit, because SSRC has changed\n");
				}
				mark = 1;
			}

			f = ast_frisolate(&srcupdate);
			AST_LIST_INSERT_TAIL(&frames, f, frame_list);

			rtp->seedrxseqno = 0;
			rtp->rxcount = 0;
			rtp->rxoctetcount = 0;
			rtp->cycles = 0;
			rtp->lastrxseqno = 0;
			rtp->last_seqno = 0;
			rtp->last_end_timestamp = 0;
			if (rtp->rtcp) {
				rtp->rtcp->expected_prior = 0;
				rtp->rtcp->received_prior = 0;
			}
		}

		rtp->themssrc = ssrc; /* Record their SSRC to put in future RR */
		rtp->themssrc_valid = 1;
	}

	prev_seqno = rtp->lastrxseqno;
	rtp->lastrxseqno = seqno;

	if (!rtp->recv_buffer) {
		/* If there is no receive buffer then we can pass back the frame directly */
		return ast_rtp_interpret(instance, srtp, &addr, read_area, res, prev_seqno);
	} else if (rtp->expectedrxseqno == -1 || seqno == rtp->expectedrxseqno) {
		rtp->expectedrxseqno = seqno + 1;

		/* If there are no buffered packets that will be placed after this frame then we can
		 * return it directly without duplicating it.
		 */
		if (!ast_data_buffer_count(rtp->recv_buffer)) {
			return ast_rtp_interpret(instance, srtp, &addr, read_area, res, prev_seqno);
		}

		if (!AST_VECTOR_REMOVE_CMP_ORDERED(&rtp->missing_seqno, seqno, find_by_value,
			AST_VECTOR_ELEM_CLEANUP_NOOP)) {
			ast_debug(2, "Packet with sequence number '%d' on RTP instance '%p' is no longer missing\n",
				seqno, instance);
		}

		/* If we don't have the next packet after this we can directly return the frame, as there is no
		 * chance it will be overwritten.
		 */
		if (!ast_data_buffer_get(rtp->recv_buffer, seqno + 1)) {
			return ast_rtp_interpret(instance, srtp, &addr, read_area, res, prev_seqno);
		}

		/* Otherwise we need to dupe the frame so that the potential processing of frames placed after
		 * it do not overwrite the data. You may be thinking that we could just add the current packet
		 * to the head of the frames list and avoid having to duplicate it but this would result in out
		 * of order packet processing by libsrtp which we are trying to avoid.
		 */
		frame = ast_frdup(ast_rtp_interpret(instance, srtp, &addr, read_area, res, seqno - 1));
		if (frame) {
			AST_LIST_INSERT_TAIL(&frames, frame, frame_list);
		}

		/* Add any additional packets that we have buffered and that are available */
		while (ast_data_buffer_count(rtp->recv_buffer)) {
			struct ast_rtp_rtcp_nack_payload *payload;

			payload = (struct ast_rtp_rtcp_nack_payload *)ast_data_buffer_remove(rtp->recv_buffer, rtp->expectedrxseqno);
			if (!payload) {
				break;
			}

			frame = ast_frdup(ast_rtp_interpret(instance, srtp, &addr, payload->buf, payload->size, rtp->expectedrxseqno - 1));
			ast_free(payload);

			if (!frame) {
				/* If this packet can't be interpeted due to being out of memory we return what we have and assume
				 * that we will determine it is a missing packet later and NACK for it.
				 */
				return AST_LIST_FIRST(&frames);
			}

			ast_debug(2, "Pulled buffered packet with sequence number '%d' to additionally return on RTP instance '%p'\n",
				frame->seqno, instance);
			AST_LIST_INSERT_TAIL(&frames, frame, frame_list);
			rtp->expectedrxseqno++;
		}

		return AST_LIST_FIRST(&frames);
	} else if ((abs(seqno - rtp->expectedrxseqno) > 100) ||
		ast_data_buffer_count(rtp->recv_buffer) == ast_data_buffer_max(rtp->recv_buffer)) {
		int inserted = 0;

		/* We have a large number of outstanding buffered packets or we've jumped far ahead in time.
		 * To compensate we dump what we have in the buffer and place the current packet in a logical
		 * spot. In the case of video we also require a full frame to give the decoding side a fighting
		 * chance.
		 */

		if (rtp->rtp_source_learn.stream_type == AST_MEDIA_TYPE_VIDEO) {
			ast_debug(2, "Source on RTP instance '%p' has wild gap or packet loss, sending FIR\n",
				instance);
			rtp_write_rtcp_fir(instance, rtp, &remote_address);
		}

		while (ast_data_buffer_count(rtp->recv_buffer)) {
			struct ast_rtp_rtcp_nack_payload *payload;

			payload = (struct ast_rtp_rtcp_nack_payload *)ast_data_buffer_remove_head(rtp->recv_buffer);
			if (!payload) {
				continue;
			}

			/* Even when dumping the receive buffer we do our best to order things, so we ensure that the
			 * packet we just received is processed in the correct order, so see if we need to insert it now.
			 */
			if (!inserted) {
				int buffer_seqno;

				buffer_seqno = ntohl(payload->buf[0]) & 0xffff;
				if (seqno < buffer_seqno) {
					frame = ast_frdup(ast_rtp_interpret(instance, srtp, &addr, read_area, res, prev_seqno));
					if (frame) {
						AST_LIST_INSERT_TAIL(&frames, frame, frame_list);
						rtp->expectedrxseqno = seqno + 1;
						prev_seqno = seqno;
						ast_debug(2, "Inserted just received packet with sequence number '%d' in correct order on RTP instance '%p'\n",
							seqno, instance);
					}
					inserted = 1;
				}
			}

			frame = ast_frdup(ast_rtp_interpret(instance, srtp, &addr, payload->buf, payload->size, prev_seqno));
			if (frame) {
				AST_LIST_INSERT_TAIL(&frames, frame, frame_list);
				prev_seqno = frame->seqno;
				ast_debug(2, "Emptying queue and returning packet with sequence number '%d' from RTP instance '%p'\n",
					frame->seqno, instance);
			}

			ast_free(payload);
		}

		if (!inserted) {
			/* This current packet goes after them, and we assume that packets going forward will follow
			 * that new sequence number increment. It is okay for this to not be duplicated as it is guaranteed
			 * to be the last packet processed right now and it is also guaranteed that it will always return
			 * non-NULL.
			 */
			frame = ast_rtp_interpret(instance, srtp, &addr, read_area, res, prev_seqno);
			AST_LIST_INSERT_TAIL(&frames, frame, frame_list);
			rtp->expectedrxseqno = seqno + 1;

			ast_debug(2, "Adding just received packet with sequence number '%d' to end of dumped queue on RTP instance '%p'\n",
				seqno, instance);
		}

		/* As there is such a large gap we don't want to flood the order side with missing packets, so we
		 * give up and start anew.
		 */
		AST_VECTOR_RESET(&rtp->missing_seqno, AST_VECTOR_ELEM_CLEANUP_NOOP);

		return AST_LIST_FIRST(&frames);
	} else if (seqno < rtp->expectedrxseqno) {
		/* If this is a packet from the past then we have received a duplicate packet, so just drop it */
		ast_debug(2, "Received an old packet with sequence number '%d' on RTP instance '%p', dropping it\n",
			seqno, instance);
		return &ast_null_frame;
	} else if (ast_data_buffer_get(rtp->recv_buffer, seqno)) {
		/* If this is a packet we already have buffered then it is a duplicate, so just drop it */
		ast_debug(2, "Received a duplicate transmission of packet with sequence number '%d' on RTP instance '%p', dropping it\n",
			seqno, instance);
		return &ast_null_frame;
	} else {
		/* This is an out of order packet from the future */
		struct ast_rtp_rtcp_nack_payload *payload;
		int difference;

		ast_debug(2, "Received an out of order packet with sequence number '%d' from the future on RTP instance '%p'\n",
			seqno, instance);

		payload = ast_malloc(sizeof(*payload) + res);
		if (!payload) {
			/* If the payload can't be allocated then we can't defer this packet right now.
			 * Instead of dumping what we have we pretend we lost this packet. It will then
			 * get NACKed later or the existing buffer will be returned entirely. Well, we may
			 * try since we're seemingly out of memory. It's a bad situation all around and
			 * packets are likely to get lost anyway.
			 */
			return &ast_null_frame;
		}

		payload->size = res;
		memcpy(payload->buf, rtpheader, res);
		ast_data_buffer_put(rtp->recv_buffer, seqno, payload);
		AST_VECTOR_REMOVE_CMP_ORDERED(&rtp->missing_seqno, seqno, find_by_value,
			AST_VECTOR_ELEM_CLEANUP_NOOP);

		difference = seqno - (prev_seqno + 1);
		while (difference > 0) {
			/* We don't want missing sequence number duplicates. If, for some reason,
			 * packets are really out of order, we could end up in this scenario:
			 *
			 * We are expecting sequence number 100
			 * We receive sequence number 105
			 * Sequence numbers 100 through 104 get added to the vector
			 * We receive sequence number 101 (this section is skipped)
			 * We receive sequence number 103
			 * Sequence number 102 is added to the vector
			 *
			 * This will prevent the duplicate from being added.
			 */
			if (AST_VECTOR_GET_CMP(&rtp->missing_seqno, seqno - difference,
						find_by_value)) {
				difference--;
				continue;
			}

			ast_debug(2, "Added missing sequence number '%d' to RTP instance '%p'\n",
				seqno - difference, instance);
			AST_VECTOR_ADD_SORTED(&rtp->missing_seqno, seqno - difference,
					compare_by_value);
			difference--;
		}

		/* When our data buffer is half full we assume that the packets aren't just out of order but
		 * have actually been lost. To get them back we construct and send a NACK causing the sender to
		 * retransmit them.
		 */
		if (ast_data_buffer_count(rtp->recv_buffer) == ast_data_buffer_max(rtp->recv_buffer) / 2) {
			int packet_len = 0;
			int res = 0;
			int ice;
			int sr;
			size_t data_size = AST_UUID_STR_LEN + 128 + (seqno - rtp->expectedrxseqno) / 17;
			RAII_VAR(unsigned char *, rtcpheader, NULL, ast_free_ptr);
			RAII_VAR(struct ast_rtp_rtcp_report *, rtcp_report,
					ast_rtp_rtcp_report_alloc(rtp->themssrc_valid ? 1 : 0),
					ao2_cleanup);

			rtcpheader = ast_malloc(sizeof(*rtcpheader) + data_size);
			if (!rtcpheader) {
				ast_debug(1, "Failed to allocate memory for NACK\n");
				return &ast_null_frame;
			}

			memset(rtcpheader, 0, data_size);

			res = ast_rtcp_generate_report(instance, rtcpheader, rtcp_report, &sr);

			if (res == 0 || res == 1) {
				ast_debug(1, "Failed to add %s report to NACK, stopping here\n", sr ? "SR" : "RR");
				return &ast_null_frame;
			}

			packet_len += res;

			res = ast_rtcp_generate_nack(instance, rtcpheader + packet_len);

			if (res == 0) {
				ast_debug(1, "Failed to construct NACK, stopping here\n");
				return &ast_null_frame;
			}

			packet_len += res;

			res = rtcp_sendto(instance, rtcpheader, packet_len, 0, &remote_address, &ice);
			if (res < 0) {
				ast_debug(1, "Failed to send NACK request out\n");
			} else {
				/* Update RTCP SR/RR statistics */
				ast_rtcp_calculate_sr_rr_statistics(instance, rtcp_report, remote_address, ice, sr);
			}

			ast_debug(2, "Sending a NACK request on RTP instance '%p' to get missing packets\n", instance);
		}

		return &ast_null_frame;
	}

	return &ast_null_frame;
}

/*! \pre instance is locked */
static void ast_rtp_prop_set(struct ast_rtp_instance *instance, enum ast_rtp_property property, int value)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (property == AST_RTP_PROPERTY_RTCP) {
		if (value) {
			struct ast_sockaddr local_addr;

			if (rtp->rtcp && rtp->rtcp->type == value) {
				ast_debug(1, "Ignoring duplicate RTCP property on RTP instance '%p'\n", instance);
				return;
			}

			if (!rtp->rtcp) {
				rtp->rtcp = ast_calloc(1, sizeof(*rtp->rtcp));
				if (!rtp->rtcp) {
					return;
				}
				rtp->rtcp->s = -1;
#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
				rtp->rtcp->dtls.timeout_timer = -1;
#endif
				rtp->rtcp->schedid = -1;
			}

			rtp->rtcp->type = value;

			/* Grab the IP address and port we are going to use */
			ast_rtp_instance_get_local_address(instance, &rtp->rtcp->us);
			if (value == AST_RTP_INSTANCE_RTCP_STANDARD) {
				ast_sockaddr_set_port(&rtp->rtcp->us,
					ast_sockaddr_port(&rtp->rtcp->us) + 1);
			}

			ast_sockaddr_copy(&local_addr, &rtp->rtcp->us);
			if (!ast_find_ourip(&local_addr, &rtp->rtcp->us, 0)) {
				ast_sockaddr_set_port(&local_addr, ast_sockaddr_port(&rtp->rtcp->us));
			} else {
				/* Failed to get local address reset to use default. */
				ast_sockaddr_copy(&local_addr, &rtp->rtcp->us);
			}

			ast_free(rtp->rtcp->local_addr_str);
			rtp->rtcp->local_addr_str = ast_strdup(ast_sockaddr_stringify(&local_addr));
			if (!rtp->rtcp->local_addr_str) {
				ast_free(rtp->rtcp);
				rtp->rtcp = NULL;
				return;
			}

			if (value == AST_RTP_INSTANCE_RTCP_STANDARD) {
				/* We're either setting up RTCP from scratch or
				 * switching from MUX. Either way, we won't have
				 * a socket set up, and we need to set it up
				 */
				if ((rtp->rtcp->s =
				     create_new_socket("RTCP",
						       ast_sockaddr_is_ipv4(&rtp->rtcp->us) ?
						       AF_INET :
						       ast_sockaddr_is_ipv6(&rtp->rtcp->us) ?
						       AF_INET6 : -1)) < 0) {
					ast_debug(1, "Failed to create a new socket for RTCP on instance '%p'\n", instance);
					ast_free(rtp->rtcp->local_addr_str);
					ast_free(rtp->rtcp);
					rtp->rtcp = NULL;
					return;
				}

				/* Try to actually bind to the IP address and port we are going to use for RTCP, if this fails we have to bail out */
				if (ast_bind(rtp->rtcp->s, &rtp->rtcp->us)) {
					ast_debug(1, "Failed to setup RTCP on RTP instance '%p'\n", instance);
					close(rtp->rtcp->s);
					ast_free(rtp->rtcp->local_addr_str);
					ast_free(rtp->rtcp);
					rtp->rtcp = NULL;
					return;
				}
#ifdef HAVE_PJPROJECT
				if (rtp->ice) {
					rtp_add_candidates_to_ice(instance, rtp, &rtp->rtcp->us, ast_sockaddr_port(&rtp->rtcp->us), AST_RTP_ICE_COMPONENT_RTCP, TRANSPORT_SOCKET_RTCP);
				}
#endif
#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
				dtls_setup_rtcp(instance);
#endif
			} else {
				struct ast_sockaddr addr;
				/* RTCPMUX uses the same socket as RTP. If we were previously using standard RTCP
				 * then close the socket we previously created.
				 *
				 * It may seem as though there is a possible race condition here where we might try
				 * to close the RTCP socket while it is being used to send data. However, this is not
				 * a problem in practice since setting and adjusting of RTCP properties happens prior
				 * to activating RTP. It is not until RTP is activated that timers start for RTCP
				 * transmission
				 */
				if (rtp->rtcp->s > -1 && rtp->rtcp->s != rtp->s) {
					close(rtp->rtcp->s);
				}
				rtp->rtcp->s = rtp->s;
				ast_rtp_instance_get_remote_address(instance, &addr);
				ast_sockaddr_copy(&rtp->rtcp->them, &addr);
#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
				if (rtp->rtcp->dtls.ssl && rtp->rtcp->dtls.ssl != rtp->dtls.ssl) {
					SSL_free(rtp->rtcp->dtls.ssl);
				}
				rtp->rtcp->dtls.ssl = rtp->dtls.ssl;
#endif
			}

			ast_debug(1, "Setup RTCP on RTP instance '%p'\n", instance);
		} else {
			if (rtp->rtcp) {
				if (rtp->rtcp->schedid > -1) {
					ao2_unlock(instance);
					if (!ast_sched_del(rtp->sched, rtp->rtcp->schedid)) {
						/* Successfully cancelled scheduler entry. */
						ao2_ref(instance, -1);
					} else {
						/* Unable to cancel scheduler entry */
						ast_debug(1, "Failed to tear down RTCP on RTP instance '%p'\n", instance);
						ao2_lock(instance);
						return;
					}
					ao2_lock(instance);
					rtp->rtcp->schedid = -1;
				}
				if (rtp->rtcp->s > -1 && rtp->rtcp->s != rtp->s) {
					close(rtp->rtcp->s);
				}
#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
				ao2_unlock(instance);
				dtls_srtp_stop_timeout_timer(instance, rtp, 1);
				ao2_lock(instance);

				if (rtp->rtcp->dtls.ssl && rtp->rtcp->dtls.ssl != rtp->dtls.ssl) {
					SSL_free(rtp->rtcp->dtls.ssl);
				}
#endif
				ast_free(rtp->rtcp->local_addr_str);
				ast_free(rtp->rtcp);
				rtp->rtcp = NULL;
			}
		}
	} else if (property == AST_RTP_PROPERTY_ASYMMETRIC_CODEC) {
		rtp->asymmetric_codec = value;
	} else if (property == AST_RTP_PROPERTY_RETRANS_SEND) {
		rtp->send_buffer = ast_data_buffer_alloc(ast_free_ptr, DEFAULT_RTP_SEND_BUFFER_SIZE);
	} else if (property == AST_RTP_PROPERTY_RETRANS_RECV) {
		rtp->recv_buffer = ast_data_buffer_alloc(ast_free_ptr, DEFAULT_RTP_RECV_BUFFER_SIZE);
		AST_VECTOR_INIT(&rtp->missing_seqno, 0);
	}
}

/*! \pre instance is locked */
static int ast_rtp_fd(struct ast_rtp_instance *instance, int rtcp)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	return rtcp ? (rtp->rtcp ? rtp->rtcp->s : -1) : rtp->s;
}

/*! \pre instance is locked */
static void ast_rtp_remote_address_set(struct ast_rtp_instance *instance, struct ast_sockaddr *addr)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr local;
	int index;

	ast_rtp_instance_get_local_address(instance, &local);
	if (!ast_sockaddr_isnull(addr)) {
		/* Update the local RTP address with what is being used */
		if (ast_ouraddrfor(addr, &local)) {
			/* Failed to update our address so reuse old local address */
			ast_rtp_instance_get_local_address(instance, &local);
		} else {
			ast_rtp_instance_set_local_address(instance, &local);
		}
	}

	if (rtp->rtcp && !ast_sockaddr_isnull(addr)) {
		ast_debug(1, "Setting RTCP address on RTP instance '%p'\n", instance);
		ast_sockaddr_copy(&rtp->rtcp->them, addr);

		if (rtp->rtcp->type == AST_RTP_INSTANCE_RTCP_STANDARD) {
			ast_sockaddr_set_port(&rtp->rtcp->them, ast_sockaddr_port(addr) + 1);

			/* Update the local RTCP address with what is being used */
			ast_sockaddr_set_port(&local, ast_sockaddr_port(&local) + 1);
		}
		ast_sockaddr_copy(&rtp->rtcp->us, &local);

		ast_free(rtp->rtcp->local_addr_str);
		rtp->rtcp->local_addr_str = ast_strdup(ast_sockaddr_stringify(&local));
	}

	/* Update any bundled RTP instances */
	for (index = 0; index < AST_VECTOR_SIZE(&rtp->ssrc_mapping); ++index) {
		struct rtp_ssrc_mapping *mapping = AST_VECTOR_GET_ADDR(&rtp->ssrc_mapping, index);

		ast_rtp_instance_set_remote_address(mapping->instance, addr);
	}

	/* Need to reset the DTMF last sequence number and the timestamp of the last END packet */
	rtp->last_seqno = 0;
	rtp->last_end_timestamp = 0;

	if (strictrtp && rtp->strict_rtp_state != STRICT_RTP_OPEN
		&& !ast_sockaddr_isnull(addr) && ast_sockaddr_cmp(addr, &rtp->strict_rtp_address)) {
		/* We only need to learn a new strict source address if we've been told the source is
		 * changing to something different.
		 */
		ast_verb(4, "%p -- Strict RTP learning after remote address set to: %s\n",
			rtp, ast_sockaddr_stringify(addr));
		rtp_learning_start(rtp);
	}
}

/*!
 * \brief Write t140 redundacy frame
 *
 * \param data primary data to be buffered
 *
 * Scheduler callback
 */
static int red_write(const void *data)
{
	struct ast_rtp_instance *instance = (struct ast_rtp_instance*) data;
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	ao2_lock(instance);
	if (rtp->red->t140.datalen > 0) {
		ast_rtp_write(instance, &rtp->red->t140);
	}
	ao2_unlock(instance);

	return 1;
}

/*! \pre instance is locked */
static int rtp_red_init(struct ast_rtp_instance *instance, int buffer_time, int *payloads, int generations)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	int x;

	rtp->red = ast_calloc(1, sizeof(*rtp->red));
	if (!rtp->red) {
		return -1;
	}

	rtp->red->t140.frametype = AST_FRAME_TEXT;
	rtp->red->t140.subclass.format = ast_format_t140_red;
	rtp->red->t140.data.ptr = &rtp->red->buf_data;

	rtp->red->t140red = rtp->red->t140;
	rtp->red->t140red.data.ptr = &rtp->red->t140red_data;

	rtp->red->ti = buffer_time;
	rtp->red->num_gen = generations;
	rtp->red->hdrlen = generations * 4 + 1;

	for (x = 0; x < generations; x++) {
		rtp->red->pt[x] = payloads[x];
		rtp->red->pt[x] |= 1 << 7; /* mark redundant generations pt */
		rtp->red->t140red_data[x*4] = rtp->red->pt[x];
	}
	rtp->red->t140red_data[x*4] = rtp->red->pt[x] = payloads[x]; /* primary pt */
	rtp->red->schedid = ast_sched_add(rtp->sched, generations, red_write, instance);

	return 0;
}

/*! \pre instance is locked */
static int rtp_red_buffer(struct ast_rtp_instance *instance, struct ast_frame *frame)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct rtp_red *red = rtp->red;

	if (!red) {
		return 0;
	}

	if (frame->datalen > 0) {
		if (red->t140.datalen > 0) {
			const unsigned char *primary = red->buf_data;

			/* There is something already in the T.140 buffer */
			if (primary[0] == 0x08 || primary[0] == 0x0a || primary[0] == 0x0d) {
				/* Flush the previous T.140 packet if it is a command */
				ast_rtp_write(instance, &rtp->red->t140);
			} else {
				primary = frame->data.ptr;
				if (primary[0] == 0x08 || primary[0] == 0x0a || primary[0] == 0x0d) {
					/* Flush the previous T.140 packet if we are buffering a command now */
					ast_rtp_write(instance, &rtp->red->t140);
				}
			}
		}

		memcpy(&red->buf_data[red->t140.datalen], frame->data.ptr, frame->datalen);
		red->t140.datalen += frame->datalen;
		red->t140.ts = frame->ts;
	}

	return 0;
}

/*! \pre Neither instance0 nor instance1 are locked */
static int ast_rtp_local_bridge(struct ast_rtp_instance *instance0, struct ast_rtp_instance *instance1)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance0);

	ao2_lock(instance0);
	ast_set_flag(rtp, FLAG_NEED_MARKER_BIT | FLAG_REQ_LOCAL_BRIDGE_BIT);
	if (rtp->smoother) {
		ast_smoother_free(rtp->smoother);
		rtp->smoother = NULL;
	}
	ao2_unlock(instance0);

	return 0;
}

/*! \pre instance is locked */
static int ast_rtp_get_stat(struct ast_rtp_instance *instance, struct ast_rtp_instance_stats *stats, enum ast_rtp_instance_stat stat)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (!rtp->rtcp) {
		return -1;
	}

	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_TXCOUNT, -1, stats->txcount, rtp->txcount);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_RXCOUNT, -1, stats->rxcount, rtp->rxcount);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_TXOCTETCOUNT, -1, stats->txoctetcount, rtp->txoctetcount);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_RXOCTETCOUNT, -1, stats->rxoctetcount, rtp->rxoctetcount);

	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_TXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->txploss, rtp->rtcp->reported_lost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_RXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->rxploss, rtp->rtcp->expected_prior - rtp->rtcp->received_prior);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_MAXRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->remote_maxrxploss, rtp->rtcp->reported_maxlost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_MINRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->remote_minrxploss, rtp->rtcp->reported_minlost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_NORMDEVRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->remote_normdevrxploss, rtp->rtcp->reported_normdev_lost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_STDEVRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->remote_stdevrxploss, rtp->rtcp->reported_stdev_lost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_MAXRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->local_maxrxploss, rtp->rtcp->maxrxlost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_MINRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->local_minrxploss, rtp->rtcp->minrxlost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_NORMDEVRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->local_normdevrxploss, rtp->rtcp->normdev_rxlost);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_STDEVRXPLOSS, AST_RTP_INSTANCE_STAT_COMBINED_LOSS, stats->local_stdevrxploss, rtp->rtcp->stdev_rxlost);
	AST_RTP_STAT_TERMINATOR(AST_RTP_INSTANCE_STAT_COMBINED_LOSS);

	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_TXJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->txjitter, rtp->rxjitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_RXJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->rxjitter, rtp->rtcp->reported_jitter / (unsigned int) 65536.0);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_MAXJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->remote_maxjitter, rtp->rtcp->reported_maxjitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_MINJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->remote_minjitter, rtp->rtcp->reported_minjitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_NORMDEVJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->remote_normdevjitter, rtp->rtcp->reported_normdev_jitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_STDEVJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->remote_stdevjitter, rtp->rtcp->reported_stdev_jitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_MAXJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->local_maxjitter, rtp->rtcp->maxrxjitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_MINJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->local_minjitter, rtp->rtcp->minrxjitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_NORMDEVJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->local_normdevjitter, rtp->rtcp->normdev_rxjitter);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_STDEVJITTER, AST_RTP_INSTANCE_STAT_COMBINED_JITTER, stats->local_stdevjitter, rtp->rtcp->stdev_rxjitter);
	AST_RTP_STAT_TERMINATOR(AST_RTP_INSTANCE_STAT_COMBINED_JITTER);

	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_RTT, AST_RTP_INSTANCE_STAT_COMBINED_RTT, stats->rtt, rtp->rtcp->rtt);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_MAX_RTT, AST_RTP_INSTANCE_STAT_COMBINED_RTT, stats->maxrtt, rtp->rtcp->maxrtt);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_MIN_RTT, AST_RTP_INSTANCE_STAT_COMBINED_RTT, stats->minrtt, rtp->rtcp->minrtt);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_NORMDEVRTT, AST_RTP_INSTANCE_STAT_COMBINED_RTT, stats->normdevrtt, rtp->rtcp->normdevrtt);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_STDEVRTT, AST_RTP_INSTANCE_STAT_COMBINED_RTT, stats->stdevrtt, rtp->rtcp->stdevrtt);
	AST_RTP_STAT_TERMINATOR(AST_RTP_INSTANCE_STAT_COMBINED_RTT);

	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_LOCAL_SSRC, -1, stats->local_ssrc, rtp->ssrc);
	AST_RTP_STAT_SET(AST_RTP_INSTANCE_STAT_REMOTE_SSRC, -1, stats->remote_ssrc, rtp->themssrc);
	AST_RTP_STAT_STRCPY(AST_RTP_INSTANCE_STAT_CHANNEL_UNIQUEID, -1, stats->channel_uniqueid, ast_rtp_instance_get_channel_id(instance));

	return 0;
}

/*! \pre Neither instance0 nor instance1 are locked */
static int ast_rtp_dtmf_compatible(struct ast_channel *chan0, struct ast_rtp_instance *instance0, struct ast_channel *chan1, struct ast_rtp_instance *instance1)
{
	/* If both sides are not using the same method of DTMF transmission
	 * (ie: one is RFC2833, other is INFO... then we can not do direct media.
	 * --------------------------------------------------
	 * | DTMF Mode |  HAS_DTMF  |  Accepts Begin Frames |
	 * |-----------|------------|-----------------------|
	 * | Inband    | False      | True                  |
	 * | RFC2833   | True       | True                  |
	 * | SIP INFO  | False      | False                 |
	 * --------------------------------------------------
	 */
	return (((ast_rtp_instance_get_prop(instance0, AST_RTP_PROPERTY_DTMF) != ast_rtp_instance_get_prop(instance1, AST_RTP_PROPERTY_DTMF)) ||
		 (!ast_channel_tech(chan0)->send_digit_begin != !ast_channel_tech(chan1)->send_digit_begin)) ? 0 : 1);
}

/*! \pre instance is NOT locked */
static void ast_rtp_stun_request(struct ast_rtp_instance *instance, struct ast_sockaddr *suggestion, const char *username)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct sockaddr_in suggestion_tmp;

	/*
	 * The instance should not be locked because we can block
	 * waiting for a STUN respone.
	 */
	ast_sockaddr_to_sin(suggestion, &suggestion_tmp);
	ast_stun_request(rtp->s, &suggestion_tmp, username, NULL);
	ast_sockaddr_from_sin(suggestion, &suggestion_tmp);
}

/*! \pre instance is locked */
static void ast_rtp_stop(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr addr = { {0,} };

#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
	ao2_unlock(instance);
	AST_SCHED_DEL_UNREF(rtp->sched, rtp->rekeyid, ao2_ref(instance, -1));

	dtls_srtp_stop_timeout_timer(instance, rtp, 0);
	if (rtp->rtcp) {
		dtls_srtp_stop_timeout_timer(instance, rtp, 1);
	}
	ao2_lock(instance);
#endif

	if (rtp->rtcp && rtp->rtcp->schedid > -1) {
		ao2_unlock(instance);
		if (!ast_sched_del(rtp->sched, rtp->rtcp->schedid)) {
			/* successfully cancelled scheduler entry. */
			ao2_ref(instance, -1);
		}
		ao2_lock(instance);
		rtp->rtcp->schedid = -1;
	}

	if (rtp->red) {
		ao2_unlock(instance);
		AST_SCHED_DEL(rtp->sched, rtp->red->schedid);
		ao2_lock(instance);
		ast_free(rtp->red);
		rtp->red = NULL;
	}

	ast_rtp_instance_set_remote_address(instance, &addr);

	ast_set_flag(rtp, FLAG_NEED_MARKER_BIT);
}

/*! \pre instance is locked */
static int ast_rtp_qos_set(struct ast_rtp_instance *instance, int tos, int cos, const char *desc)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	return ast_set_qos(rtp->s, tos, cos, desc);
}

/*!
 * \brief generate comfort noice (CNG)
 *
 * \pre instance is locked
 */
static int ast_rtp_sendcng(struct ast_rtp_instance *instance, int level)
{
	unsigned int *rtpheader;
	int hdrlen = 12;
	int res, payload = 0;
	char data[256];
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);
	struct ast_sockaddr remote_address = { {0,} };
	int ice;

	ast_rtp_instance_get_remote_address(instance, &remote_address);

	if (ast_sockaddr_isnull(&remote_address)) {
		return -1;
	}

	payload = ast_rtp_codecs_payload_code_tx(ast_rtp_instance_get_codecs(instance), 0, NULL, AST_RTP_CN);

	level = 127 - (level & 0x7f);

	rtp->dtmfmute = ast_tvadd(ast_tvnow(), ast_tv(0, 500000));

	/* Get a pointer to the header */
	rtpheader = (unsigned int *)data;
	rtpheader[0] = htonl((2 << 30) | (payload << 16) | (rtp->seqno));
	rtpheader[1] = htonl(rtp->lastts);
	rtpheader[2] = htonl(rtp->ssrc);
	data[12] = level;

	res = rtp_sendto(instance, (void *) rtpheader, hdrlen + 1, 0, &remote_address, &ice);

	if (res < 0) {
		ast_log(LOG_ERROR, "RTP Comfort Noise Transmission error to %s: %s\n", ast_sockaddr_stringify(&remote_address), strerror(errno));
		return res;
	}

	if (rtp_debug_test_addr(&remote_address)) {
		ast_verbose("Sent Comfort Noise RTP packet to %s%s (type %-2.2d, seq %-6.6d, ts %-6.6u, len %-6.6d)\n",
			    ast_sockaddr_stringify(&remote_address),
			    ice ? " (via ICE)" : "",
			    AST_RTP_CN, rtp->seqno, rtp->lastdigitts, res - hdrlen);
	}

	rtp->seqno++;

	return res;
}

/*! \pre instance is locked */
static unsigned int ast_rtp_get_ssrc(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	return rtp->ssrc;
}

/*! \pre instance is locked */
static const char *ast_rtp_get_cname(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	return rtp->cname;
}

/*! \pre instance is locked */
static void ast_rtp_set_remote_ssrc(struct ast_rtp_instance *instance, unsigned int ssrc)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	if (rtp->themssrc_valid && rtp->themssrc == ssrc) {
		return;
	}

	rtp->themssrc = ssrc;
	rtp->themssrc_valid = 1;

	/* If this is bundled we need to update the SSRC mapping */
	if (rtp->bundled) {
		struct ast_rtp *bundled_rtp;
		int index;

		ao2_unlock(instance);

		/* The child lock can't be held while accessing the parent */
		ao2_lock(rtp->bundled);
		bundled_rtp = ast_rtp_instance_get_data(rtp->bundled);

		for (index = 0; index < AST_VECTOR_SIZE(&bundled_rtp->ssrc_mapping); ++index) {
			struct rtp_ssrc_mapping *mapping = AST_VECTOR_GET_ADDR(&bundled_rtp->ssrc_mapping, index);

			if (mapping->instance == instance) {
				mapping->ssrc = ssrc;
				mapping->ssrc_valid = 1;
				break;
			}
		}

		ao2_unlock(rtp->bundled);

		ao2_lock(instance);
	}
}

static void ast_rtp_set_stream_num(struct ast_rtp_instance *instance, int stream_num)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	rtp->stream_num = stream_num;
}

static int ast_rtp_extension_enable(struct ast_rtp_instance *instance, enum ast_rtp_extension extension)
{
	switch (extension) {
	case AST_RTP_EXTENSION_ABS_SEND_TIME:
		return 1;
	default:
		return 0;
	}
}

/*! \pre child is locked */
static int ast_rtp_bundle(struct ast_rtp_instance *child, struct ast_rtp_instance *parent)
{
	struct ast_rtp *child_rtp = ast_rtp_instance_get_data(child);
	struct ast_rtp *parent_rtp;
	struct rtp_ssrc_mapping mapping;
	struct ast_sockaddr them = { { 0, } };

	if (child_rtp->bundled == parent) {
		return 0;
	}

	/* If this instance was already bundled then remove the SSRC mapping */
	if (child_rtp->bundled) {
		struct ast_rtp *bundled_rtp;

		ao2_unlock(child);

		/* The child lock can't be held while accessing the parent */
		ao2_lock(child_rtp->bundled);
		bundled_rtp = ast_rtp_instance_get_data(child_rtp->bundled);
		AST_VECTOR_REMOVE_CMP_UNORDERED(&bundled_rtp->ssrc_mapping, child, SSRC_MAPPING_ELEM_CMP, AST_VECTOR_ELEM_CLEANUP_NOOP);
		ao2_unlock(child_rtp->bundled);

		ao2_lock(child);
		ao2_ref(child_rtp->bundled, -1);
		child_rtp->bundled = NULL;
	}

	if (!parent) {
		/* We transitioned away from bundle so we need our own transport resources once again */
		rtp_allocate_transport(child, child_rtp);
		return 0;
	}

	parent_rtp = ast_rtp_instance_get_data(parent);

	/* We no longer need any transport related resources as we will use our parent RTP instance instead */
	rtp_deallocate_transport(child, child_rtp);

	/* Children maintain a reference to the parent to guarantee that the transport doesn't go away on them */
	child_rtp->bundled = ao2_bump(parent);

	mapping.ssrc = child_rtp->themssrc;
	mapping.ssrc_valid = child_rtp->themssrc_valid;
	mapping.instance = child;

	ao2_unlock(child);

	ao2_lock(parent);

	AST_VECTOR_APPEND(&parent_rtp->ssrc_mapping, mapping);

#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
	/* If DTLS-SRTP is already in use then add the local SSRC to it, otherwise it will get added once DTLS
	 * negotiation has been completed.
	 */
	if (parent_rtp->dtls.connection == AST_RTP_DTLS_CONNECTION_EXISTING) {
		dtls_srtp_add_local_ssrc(parent_rtp, parent, 0, child_rtp->ssrc, 0);
	}
#endif

	/* Bundle requires that RTCP-MUX be in use so only the main remote address needs to match */
	ast_rtp_instance_get_remote_address(parent, &them);

	ao2_unlock(parent);

	ao2_lock(child);

	ast_rtp_instance_set_remote_address(child, &them);

	return 0;
}

#if defined(HAVE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10001000L) && !defined(OPENSSL_NO_SRTP)
/*! \pre instance is locked */
static int ast_rtp_activate(struct ast_rtp_instance *instance)
{
	struct ast_rtp *rtp = ast_rtp_instance_get_data(instance);

	/* If ICE negotiation is enabled the DTLS Handshake will be performed upon completion of it */
#ifdef HAVE_PJPROJECT
	if (rtp->ice) {
		return 0;
	}
#endif

	dtls_perform_setup(&rtp->dtls);
	dtls_perform_handshake(instance, &rtp->dtls, 0);

	if (rtp->rtcp && rtp->rtcp->type == AST_RTP_INSTANCE_RTCP_STANDARD) {
		dtls_perform_setup(&rtp->rtcp->dtls);
		dtls_perform_handshake(instance, &rtp->rtcp->dtls, 1);
	}

	return 0;
}
#endif

static char *rtp_do_debug_ip(struct ast_cli_args *a)
{
	char *arg = ast_strdupa(a->argv[4]);
	char *debughost = NULL;
	char *debugport = NULL;

	if (!ast_sockaddr_parse(&rtpdebugaddr, arg, 0) || !ast_sockaddr_split_hostport(arg, &debughost, &debugport, 0)) {
		ast_cli(a->fd, "Lookup failed for '%s'\n", arg);
		return CLI_FAILURE;
	}
	rtpdebugport = (!ast_strlen_zero(debugport) && debugport[0] != '0');
	ast_cli(a->fd, "RTP Debugging Enabled for address: %s\n",
		ast_sockaddr_stringify(&rtpdebugaddr));
	rtpdebug = 1;
	return CLI_SUCCESS;
}

static char *rtcp_do_debug_ip(struct ast_cli_args *a)
{
	char *arg = ast_strdupa(a->argv[4]);
	char *debughost = NULL;
	char *debugport = NULL;

	if (!ast_sockaddr_parse(&rtcpdebugaddr, arg, 0) || !ast_sockaddr_split_hostport(arg, &debughost, &debugport, 0)) {
		ast_cli(a->fd, "Lookup failed for '%s'\n", arg);
		return CLI_FAILURE;
	}
	rtcpdebugport = (!ast_strlen_zero(debugport) && debugport[0] != '0');
	ast_cli(a->fd, "RTCP Debugging Enabled for address: %s\n",
		ast_sockaddr_stringify(&rtcpdebugaddr));
	rtcpdebug = 1;
	return CLI_SUCCESS;
}

static char *handle_cli_rtp_set_debug(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "rtp set debug {on|off|ip}";
		e->usage =
			"Usage: rtp set debug {on|off|ip host[:port]}\n"
			"       Enable/Disable dumping of all RTP packets. If 'ip' is\n"
			"       specified, limit the dumped packets to those to and from\n"
			"       the specified 'host' with optional port.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc == e->args) { /* set on or off */
		if (!strncasecmp(a->argv[e->args-1], "on", 2)) {
			rtpdebug = 1;
			memset(&rtpdebugaddr, 0, sizeof(rtpdebugaddr));
			ast_cli(a->fd, "RTP Debugging Enabled\n");
			return CLI_SUCCESS;
		} else if (!strncasecmp(a->argv[e->args-1], "off", 3)) {
			rtpdebug = 0;
			ast_cli(a->fd, "RTP Debugging Disabled\n");
			return CLI_SUCCESS;
		}
	} else if (a->argc == e->args +1) { /* ip */
		return rtp_do_debug_ip(a);
	}

	return CLI_SHOWUSAGE;   /* default, failure */
}

static char *handle_cli_rtcp_set_debug(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "rtcp set debug {on|off|ip}";
		e->usage =
			"Usage: rtcp set debug {on|off|ip host[:port]}\n"
			"       Enable/Disable dumping of all RTCP packets. If 'ip' is\n"
			"       specified, limit the dumped packets to those to and from\n"
			"       the specified 'host' with optional port.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc == e->args) { /* set on or off */
		if (!strncasecmp(a->argv[e->args-1], "on", 2)) {
			rtcpdebug = 1;
			memset(&rtcpdebugaddr, 0, sizeof(rtcpdebugaddr));
			ast_cli(a->fd, "RTCP Debugging Enabled\n");
			return CLI_SUCCESS;
		} else if (!strncasecmp(a->argv[e->args-1], "off", 3)) {
			rtcpdebug = 0;
			ast_cli(a->fd, "RTCP Debugging Disabled\n");
			return CLI_SUCCESS;
		}
	} else if (a->argc == e->args +1) { /* ip */
		return rtcp_do_debug_ip(a);
	}

	return CLI_SHOWUSAGE;   /* default, failure */
}

static char *handle_cli_rtcp_set_stats(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "rtcp set stats {on|off}";
		e->usage =
			"Usage: rtcp set stats {on|off}\n"
			"       Enable/Disable dumping of RTCP stats.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != e->args)
		return CLI_SHOWUSAGE;

	if (!strncasecmp(a->argv[e->args-1], "on", 2))
		rtcpstats = 1;
	else if (!strncasecmp(a->argv[e->args-1], "off", 3))
		rtcpstats = 0;
	else
		return CLI_SHOWUSAGE;

	ast_cli(a->fd, "RTCP Stats %s\n", rtcpstats ? "Enabled" : "Disabled");
	return CLI_SUCCESS;
}

static struct ast_cli_entry cli_rtp[] = {
	AST_CLI_DEFINE(handle_cli_rtp_set_debug,  "Enable/Disable RTP debugging"),
	AST_CLI_DEFINE(handle_cli_rtcp_set_debug, "Enable/Disable RTCP debugging"),
	AST_CLI_DEFINE(handle_cli_rtcp_set_stats, "Enable/Disable RTCP stats"),
};

#ifdef HAVE_PJPROJECT
/*!
 * \internal
 * \brief Clear the configured blacklist.
 * \since 13.16.0
 *
 * \param lock R/W lock protecting the blacklist
 * \param blacklist List to clear
 *
 * \return Nothing
 */
static void blacklist_clear(ast_rwlock_t *lock, struct ast_ha **blacklist)
{
	ast_rwlock_wrlock(lock);
	ast_free_ha(*blacklist);
	*blacklist = NULL;
	ast_rwlock_unlock(lock);
}

/*!
 * \internal
 * \brief Load the blacklist configuration.
 * \since 13.16.0
 *
 * \param cfg Raw config file options.
 * \param option_name Blacklist option name
 * \param lock R/W lock protecting the blacklist
 * \param blacklist List to load
 *
 * \return Nothing
 */
static void blacklist_config_load(struct ast_config *cfg, const char *option_name,
	ast_rwlock_t *lock, struct ast_ha **blacklist)
{
	struct ast_variable *var;

	ast_rwlock_wrlock(lock);
	for (var = ast_variable_browse(cfg, "general"); var; var = var->next) {
		if (!strcasecmp(var->name, option_name)) {
			struct ast_ha *na;
			int ha_error = 0;

			na = ast_append_ha("d", var->value, *blacklist, &ha_error);
			if (!na) {
				ast_log(LOG_WARNING, "Invalid %s value: %s\n",
					option_name, var->value);
			} else {
				*blacklist = na;
			}
			if (ha_error) {
				ast_log(LOG_ERROR,
					"Bad %s configuration value line %d: %s\n",
					option_name, var->lineno, var->value);
			}
		}
	}
	ast_rwlock_unlock(lock);
}
#endif

static int rtp_reload(int reload)
{
	struct ast_config *cfg;
	const char *s;
	struct ast_flags config_flags = { reload ? CONFIG_FLAG_FILEUNCHANGED : 0 };

#ifdef HAVE_PJPROJECT
	struct ast_variable *var;
	struct ast_ice_host_candidate *candidate;
#endif

	cfg = ast_config_load2("rtp.conf", "rtp", config_flags);
	if (!cfg || cfg == CONFIG_STATUS_FILEUNCHANGED || cfg == CONFIG_STATUS_FILEINVALID) {
		return 0;
	}

#ifdef SO_NO_CHECK
	nochecksums = 0;
#endif

	rtpstart = DEFAULT_RTP_START;
	rtpend = DEFAULT_RTP_END;
	rtcpinterval = RTCP_DEFAULT_INTERVALMS;
	dtmftimeout = DEFAULT_DTMF_TIMEOUT;
	strictrtp = DEFAULT_STRICT_RTP;
	learning_min_sequential = DEFAULT_LEARNING_MIN_SEQUENTIAL;
	learning_min_duration = DEFAULT_LEARNING_MIN_DURATION;

	/** This resource is not "reloaded" so much as unloaded and loaded again.
	 * In the case of the TURN related variables, the memory referenced by a
	 * previously loaded instance  *should* have been released when the
	 * corresponding pool was destroyed. If at some point in the future this
	 * resource were to support ACTUAL live reconfiguration and did NOT release
	 * the pool this will cause a small memory leak.
	 */

#ifdef HAVE_PJPROJECT
	icesupport = DEFAULT_ICESUPPORT;
	turnport = DEFAULT_TURN_PORT;
	memset(&stunaddr, 0, sizeof(stunaddr));
	turnaddr = pj_str(NULL);
	turnusername = pj_str(NULL);
	turnpassword = pj_str(NULL);
	host_candidate_overrides_clear();
	blacklist_clear(&ice_blacklist_lock, &ice_blacklist);
	blacklist_clear(&stun_blacklist_lock, &stun_blacklist);
#endif

	if ((s = ast_variable_retrieve(cfg, "general", "rtpstart"))) {
		rtpstart = atoi(s);
		if (rtpstart < MINIMUM_RTP_PORT)
			rtpstart = MINIMUM_RTP_PORT;
		if (rtpstart > MAXIMUM_RTP_PORT)
			rtpstart = MAXIMUM_RTP_PORT;
	}
	if ((s = ast_variable_retrieve(cfg, "general", "rtpend"))) {
		rtpend = atoi(s);
		if (rtpend < MINIMUM_RTP_PORT)
			rtpend = MINIMUM_RTP_PORT;
		if (rtpend > MAXIMUM_RTP_PORT)
			rtpend = MAXIMUM_RTP_PORT;
	}
	if ((s = ast_variable_retrieve(cfg, "general", "rtcpinterval"))) {
		rtcpinterval = atoi(s);
		if (rtcpinterval == 0)
			rtcpinterval = 0; /* Just so we're clear... it's zero */
		if (rtcpinterval < RTCP_MIN_INTERVALMS)
			rtcpinterval = RTCP_MIN_INTERVALMS; /* This catches negative numbers too */
		if (rtcpinterval > RTCP_MAX_INTERVALMS)
			rtcpinterval = RTCP_MAX_INTERVALMS;
	}
	if ((s = ast_variable_retrieve(cfg, "general", "rtpchecksums"))) {
#ifdef SO_NO_CHECK
		nochecksums = ast_false(s) ? 1 : 0;
#else
		if (ast_false(s))
			ast_log(LOG_WARNING, "Disabling RTP checksums is not supported on this operating system!\n");
#endif
	}
	if ((s = ast_variable_retrieve(cfg, "general", "dtmftimeout"))) {
		dtmftimeout = atoi(s);
		if ((dtmftimeout < 0) || (dtmftimeout > 64000)) {
			ast_log(LOG_WARNING, "DTMF timeout of '%d' outside range, using default of '%d' instead\n",
				dtmftimeout, DEFAULT_DTMF_TIMEOUT);
			dtmftimeout = DEFAULT_DTMF_TIMEOUT;
		};
	}
	if ((s = ast_variable_retrieve(cfg, "general", "strictrtp"))) {
		if (ast_true(s)) {
			strictrtp = STRICT_RTP_YES;
		} else if (!strcasecmp(s, "seqno")) {
			strictrtp = STRICT_RTP_SEQNO;
		} else {
			strictrtp = STRICT_RTP_NO;
		}
	}
	if ((s = ast_variable_retrieve(cfg, "general", "probation"))) {
		if ((sscanf(s, "%d", &learning_min_sequential) != 1) || learning_min_sequential <= 1) {
			ast_log(LOG_WARNING, "Value for 'probation' could not be read, using default of '%d' instead\n",
				DEFAULT_LEARNING_MIN_SEQUENTIAL);
			learning_min_sequential = DEFAULT_LEARNING_MIN_SEQUENTIAL;
		}
		learning_min_duration = CALC_LEARNING_MIN_DURATION(learning_min_sequential);
	}
#ifdef HAVE_PJPROJECT
	if ((s = ast_variable_retrieve(cfg, "general", "icesupport"))) {
		icesupport = ast_true(s);
	}
	if ((s = ast_variable_retrieve(cfg, "general", "stunaddr"))) {
		stunaddr.sin_port = htons(STANDARD_STUN_PORT);
		if (ast_parse_arg(s, PARSE_INADDR, &stunaddr)) {
			ast_log(LOG_WARNING, "Invalid STUN server address: %s\n", s);
		}
	}
	if ((s = ast_variable_retrieve(cfg, "general", "turnaddr"))) {
		struct sockaddr_in addr;
		addr.sin_port = htons(DEFAULT_TURN_PORT);
		if (ast_parse_arg(s, PARSE_INADDR, &addr)) {
			ast_log(LOG_WARNING, "Invalid TURN server address: %s\n", s);
		} else {
			pj_strdup2_with_null(pool, &turnaddr, ast_inet_ntoa(addr.sin_addr));
			/* ntohs() is not a bug here. The port number is used in host byte order with
			 * a pjnat API. */
			turnport = ntohs(addr.sin_port);
		}
	}
	if ((s = ast_variable_retrieve(cfg, "general", "turnusername"))) {
		pj_strdup2_with_null(pool, &turnusername, s);
	}
	if ((s = ast_variable_retrieve(cfg, "general", "turnpassword"))) {
		pj_strdup2_with_null(pool, &turnpassword, s);
	}

	AST_RWLIST_WRLOCK(&host_candidates);
	for (var = ast_variable_browse(cfg, "ice_host_candidates"); var; var = var->next) {
		struct ast_sockaddr local_addr, advertised_addr;
		pj_str_t address;
		unsigned int include_local_address = 0;
		char *sep;

		ast_sockaddr_setnull(&local_addr);
		ast_sockaddr_setnull(&advertised_addr);

		if (ast_parse_arg(var->name, PARSE_ADDR | PARSE_PORT_IGNORE, &local_addr)) {
			ast_log(LOG_WARNING, "Invalid local ICE host address: %s\n", var->name);
			continue;
		}

		sep = strchr(var->value,',');
		if (sep) {
			*sep = '\0';
			sep++;
			sep = ast_skip_blanks(sep);
			include_local_address = strcmp(sep, "include_local_address") == 0;
		}

		if (ast_parse_arg(var->value, PARSE_ADDR | PARSE_PORT_IGNORE, &advertised_addr)) {
			ast_log(LOG_WARNING, "Invalid advertised ICE host address: %s\n", var->value);
			continue;
		}

		if (!(candidate = ast_calloc(1, sizeof(*candidate)))) {
			ast_log(LOG_ERROR, "Failed to allocate ICE host candidate mapping.\n");
			break;
		}

		candidate->include_local = include_local_address;

		pj_sockaddr_parse(pj_AF_UNSPEC(), 0, pj_cstr(&address, ast_sockaddr_stringify(&local_addr)), &candidate->local);
		pj_sockaddr_parse(pj_AF_UNSPEC(), 0, pj_cstr(&address, ast_sockaddr_stringify(&advertised_addr)), &candidate->advertised);

		AST_RWLIST_INSERT_TAIL(&host_candidates, candidate, next);
	}
	AST_RWLIST_UNLOCK(&host_candidates);

	/* Read ICE blacklist configuration lines */
	blacklist_config_load(cfg, "ice_blacklist", &ice_blacklist_lock, &ice_blacklist);

	/* Read STUN blacklist configuration lines */
	blacklist_config_load(cfg, "stun_blacklist", &stun_blacklist_lock, &stun_blacklist);
#endif

	ast_config_destroy(cfg);

	if (rtpstart >= rtpend) {
		ast_log(LOG_WARNING, "Unreasonable values for RTP start/end port in rtp.conf\n");
		rtpstart = DEFAULT_RTP_START;
		rtpend = DEFAULT_RTP_END;
	}
	ast_verb(2, "RTP Allocating from port range %d -> %d\n", rtpstart, rtpend);
	return 0;
}

static int reload_module(void)
{
	rtp_reload(1);
	return 0;
}

#ifdef HAVE_PJPROJECT
static void rtp_terminate_pjproject(void)
{
	pj_thread_register_check();

	if (timer_thread) {
		timer_terminate = 1;
		pj_thread_join(timer_thread);
		pj_thread_destroy(timer_thread);
	}

	ast_pjproject_caching_pool_destroy(&cachingpool);
	pj_shutdown();
}
#endif

static int load_module(void)
{
#ifdef HAVE_PJPROJECT
	pj_lock_t *lock;

	AST_PJPROJECT_INIT_LOG_LEVEL();
	if (pj_init() != PJ_SUCCESS) {
		return AST_MODULE_LOAD_DECLINE;
	}

	if (pjlib_util_init() != PJ_SUCCESS) {
		rtp_terminate_pjproject();
		return AST_MODULE_LOAD_DECLINE;
	}

	if (pjnath_init() != PJ_SUCCESS) {
		rtp_terminate_pjproject();
		return AST_MODULE_LOAD_DECLINE;
	}

	ast_pjproject_caching_pool_init(&cachingpool, &pj_pool_factory_default_policy, 0);

	pool = pj_pool_create(&cachingpool.factory, "timer", 512, 512, NULL);

	if (pj_timer_heap_create(pool, 100, &timer_heap) != PJ_SUCCESS) {
		rtp_terminate_pjproject();
		return AST_MODULE_LOAD_DECLINE;
	}

	if (pj_lock_create_recursive_mutex(pool, "rtp%p", &lock) != PJ_SUCCESS) {
		rtp_terminate_pjproject();
		return AST_MODULE_LOAD_DECLINE;
	}

	pj_timer_heap_set_lock(timer_heap, lock, PJ_TRUE);

	if (pj_thread_create(pool, "timer", &timer_worker_thread, NULL, 0, 0, &timer_thread) != PJ_SUCCESS) {
		rtp_terminate_pjproject();
		return AST_MODULE_LOAD_DECLINE;
	}

#endif

	if (ast_rtp_engine_register(&asterisk_rtp_engine)) {
#ifdef HAVE_PJPROJECT
		rtp_terminate_pjproject();
#endif
		return AST_MODULE_LOAD_DECLINE;
	}

	if (ast_cli_register_multiple(cli_rtp, ARRAY_LEN(cli_rtp))) {
#ifdef HAVE_PJPROJECT
		ast_rtp_engine_unregister(&asterisk_rtp_engine);
		rtp_terminate_pjproject();
#endif
		return AST_MODULE_LOAD_DECLINE;
	}

	rtp_reload(0);

	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	ast_rtp_engine_unregister(&asterisk_rtp_engine);
	ast_cli_unregister_multiple(cli_rtp, ARRAY_LEN(cli_rtp));

#ifdef HAVE_PJPROJECT
	host_candidate_overrides_clear();
	pj_thread_register_check();
	rtp_terminate_pjproject();
#endif

	return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Asterisk RTP Stack",
	.support_level = AST_MODULE_SUPPORT_CORE,
	.load = load_module,
	.unload = unload_module,
	.reload = reload_module,
	.load_pri = AST_MODPRI_CHANNEL_DEPEND,
#ifdef HAVE_PJPROJECT
	.requires = "res_pjproject",
#endif
);
