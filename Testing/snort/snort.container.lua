---------------------------------------------------------------------------
-- H-IDS Snort 3 configuration — IN-CONTAINER variant.
--
-- Sibling of snort.lua (which targets the WSL-bridge dev workflow). This
-- copy is baked into the API Docker image at /etc/snort/snort.lua. The
-- only differences from the WSL variant are the absolute paths:
--   * dofile() points at Ubuntu's snort3 package location.
--   * ips.include points at a container path under /etc/snort.
---------------------------------------------------------------------------

HOME_NET     = 'any'
EXTERNAL_NET = 'any'

-- Ubuntu 24.04 `snort3` package installs the defaults file at this path.
dofile('/etc/snort/snort_defaults.lua')

stream      = {}
stream_ip   = {}
stream_icmp = {}
stream_tcp  = {}
stream_udp  = {}

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

ips = {
    enable_builtin_rules = false,
    include = '/etc/snort/etopen.rules',
    variables = default_variables,
}

alert_json = {
    file = true,
    -- Roll the JSON log at 100 MB. On the live host-IDS path (snort_live -i)
    -- this prevents unbounded growth from filling the EC2 EBS volume over
    -- hours of internet background traffic; Snort rolls to a timestamped file
    -- and the snort_tailer handles the inode change transparently. Harmless
    -- to the short-lived offline `-r <pcap>` replays that share this config.
    limit = 100,
    fields = 'timestamp seconds action class priority msg sid gid rev '
          .. 'src_addr src_port src_ap dst_addr dst_port dst_ap '
          .. 'proto pkt_num pkt_len iface dir service '
          .. 'tcp_flags tcp_ack tcp_seq tcp_win tcp_len '
          .. 'icmp_type icmp_code icmp_id icmp_seq '
          .. 'udp_len ttl ip_id ip_len rule',
}
