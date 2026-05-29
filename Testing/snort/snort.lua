---------------------------------------------------------------------------
-- H-IDS Snort 3 configuration — full inspector chain + ETOpen ruleset.
--
-- Topology (unchanged from B7):
--   * Snort runs in WSL (Ubuntu-24.04), reads PCAPs and writes alert_json
--     via /mnt/f/GradProject/.
--   * Windows-side tailer (app/core/snort_tailer_worker.py) reads the same
--     alert_json.txt file through the host filesystem.
--   * Project-local everywhere — no /etc/snort/, no /var/log/snort/, no sudo.
--
-- 2026-05-22 — wired snort_defaults.lua + full inspector chain so the ETOpen
-- ruleset's HTTP/DNS/FTP/SMTP signatures actually match. Previous minimal
-- config was a SYN-flood detector pretending to be Snort; this config is
-- production-grade signature coverage.
---------------------------------------------------------------------------

HOME_NET     = 'any'
EXTERNAL_NET = 'any'

-- Pull in the install-default network/port variables AND the canonical
-- inspector helper tables (default_wizard, default_ftp_server, etc.).
-- We `dofile` rather than `require` because the source-build install
-- doesn't put /usr/local/etc/snort/ on Lua's package.path.
dofile('/usr/local/etc/snort/snort_defaults.lua')

------------------------------------------------------------------------
-- Stream / IP defragmentation — enable defaults so TCP reassembly works
-- before the rules see traffic.
------------------------------------------------------------------------
stream      = {}
stream_ip   = {}
stream_icmp = {}
stream_tcp  = {}
stream_udp  = {}

------------------------------------------------------------------------
-- Application-layer inspectors — required for ETOpen's HTTP/DNS/FTP/SMTP
-- content rules. Default tables come from snort_defaults.lua.
------------------------------------------------------------------------
http_inspect = {}
ftp_server   = default_ftp_server
ftp_client   = {}
ftp_data     = {}
telnet       = {}
dns          = {}
ssh          = {}
imap         = {}
pop          = {}
smtp         = default_smtp

------------------------------------------------------------------------
-- Service detection. The wizard inspects unbound TCP/UDP flows and
-- decides which protocol inspector to invoke. The binder routes flows
-- to the appropriate inspector based on detected service.
------------------------------------------------------------------------
wizard = default_wizard

binder = {
    { when = { service = 'http' },     use = { type = 'http_inspect' } },
    { when = { service = 'ftp' },      use = { type = 'ftp_server'   } },
    { when = { service = 'ftp-data' }, use = { type = 'ftp_data'     } },
    { when = { service = 'telnet' },   use = { type = 'telnet'       } },
    { when = { service = 'ssh' },      use = { type = 'ssh'          } },
    { when = { service = 'dns' },      use = { type = 'dns'          } },
    { when = { service = 'imap' },     use = { type = 'imap'         } },
    { when = { service = 'pop3' },     use = { type = 'pop'          } },
    { when = { service = 'smtp' },     use = { type = 'smtp'         } },
    { use = { type = 'wizard' } },
}

------------------------------------------------------------------------
-- IPS engine + rules.
--   * `include = ".../etopen.rules"` pulls in the curated ETOpen subset
--     (8 categories ≈ 27k rules) plus our one baseline rule.
--   * builtin rules off — we want explicit signature coverage only.
------------------------------------------------------------------------
ips = {
    enable_builtin_rules = false,
    include = '/mnt/f/GradProject/Testing/snort/etopen.rules',
    -- IPS rule variables ($HOME_NET, $HTTP_PORTS, $HTTP_SERVERS, …) come
    -- from snort_defaults.lua's `default_variables` table. Without this
    -- assignment the ETOpen rules fail to load with "Undefined variable"
    -- errors at the first rule that references $HOME_NET or $HTTP_PORTS.
    variables = default_variables,
}

------------------------------------------------------------------------
-- Alert output — JSON, one event per line. Same field set as B7 so the
-- tailer (app/core/snort_tailer_worker.py) parses unchanged.
------------------------------------------------------------------------
alert_json = {
    file = true,
    limit = 0,
    fields = 'timestamp seconds action class priority msg sid gid rev '
          .. 'src_addr src_port src_ap dst_addr dst_port dst_ap '
          .. 'proto pkt_num pkt_len iface dir service '
          .. 'tcp_flags tcp_ack tcp_seq tcp_win tcp_len '
          .. 'icmp_type icmp_code icmp_id icmp_seq '
          .. 'udp_len ttl ip_id ip_len rule',
}
