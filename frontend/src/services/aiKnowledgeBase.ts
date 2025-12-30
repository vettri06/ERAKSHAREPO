export const AI_RISK_FACTORS = {
  iot_device_risk_multiplier: 1.5,
  router_risk_multiplier: 2.0,
  camera_risk_multiplier: 1.8,
  unknown_device_risk_multiplier: 1.3,
  recent_vuln_weight: 1.2,
  exploit_available_weight: 1.5
};
export const PRODUCT_DATABASE: Record<string, { vendor: string; category: string; first_release_year: number; cpe_prefix: string; valid_keywords: string[] }> = {
  'unbound': {
    vendor: 'nlnetlabs',
    category: 'dns-resolver',
    first_release_year: 2007,
    cpe_prefix: 'cpe:2.3:a:nlnetlabs:unbound:',
    valid_keywords: ['unbound', 'dns', 'resolver']
  },
  'dnsmasq': {
    vendor: 'dnsmasq',
    category: 'dns-dhcp',
    first_release_year: 2000,
    cpe_prefix: 'cpe:2.3:a:thekelleys:dnsmasq:',
    valid_keywords: ['dnsmasq', 'dns', 'dhcp']
  },
  'nginx': {
    vendor: 'nginx',
    category: 'web-server',
    first_release_year: 2004,
    cpe_prefix: 'cpe:2.3:a:nginx:nginx:',
    valid_keywords: ['nginx', 'http', 'server']
  },
  'lighttpd': {
    vendor: 'lighttpd',
    category: 'web-server',
    first_release_year: 2003,
    cpe_prefix: 'cpe:2.3:a:lighttpd:lighttpd:',
    valid_keywords: ['lighttpd', 'lighty']
  },
  'apache': {
    vendor: 'apache',
    category: 'web-server',
    first_release_year: 1995,
    cpe_prefix: 'cpe:2.3:a:apache:http_server:',
    valid_keywords: ['apache', 'httpd', 'http server']
  },
  'openssh': {
    vendor: 'openssh',
    category: 'ssh-server',
    first_release_year: 1999,
    cpe_prefix: 'cpe:2.3:a:openbsd:openssh:',
    valid_keywords: ['openssh', 'ssh']
  },
  'dropbear': {
    vendor: 'dropbear',
    category: 'ssh-server',
    first_release_year: 2004,
    cpe_prefix: 'cpe:2.3:a:dropbear_project:dropbear:',
    valid_keywords: ['dropbear']
  },
  'vsftpd': {
    vendor: 'vsftpd',
    category: 'ftp-server',
    first_release_year: 2001,
    cpe_prefix: 'cpe:2.3:a:vsftpd_project:vsftpd:',
    valid_keywords: ['vsftpd', 'ftp']
  },
  'postfix': {
    vendor: 'postfix',
    category: 'smtp-server',
    first_release_year: 1998,
    cpe_prefix: 'cpe:2.3:a:postfix:postfix:',
    valid_keywords: ['postfix', 'smtp']
  },
  'bind': {
    vendor: 'isc',
    category: 'dns-server',
    first_release_year: 1984,
    cpe_prefix: 'cpe:2.3:a:isc:bind:',
    valid_keywords: ['bind', 'named', 'dns']
  }
};
export const SERVICE_TO_PRODUCT = {
  'http': {
    products: ['nginx', 'apache', 'lighttpd'],
    confidence: 'LOW',
    generic_risk: {
      severity: 'MEDIUM',
      title: 'Exposed HTTP service',
      description: 'Unknown web server implementation exposed',
      confidence: 'LOW',
      ai_risk_score: 0.6
    }
  },
  'https': {
    products: ['nginx', 'apache', 'lighttpd'],
    confidence: 'LOW',
    generic_risk: {
      severity: 'MEDIUM',
      title: 'Exposed HTTPS service',
      description: 'Unknown web server with TLS exposed',
      confidence: 'LOW',
      ai_risk_score: 0.5
    }
  },
  'ssh': {
    products: ['openssh', 'dropbear'],
    confidence: 'MEDIUM',
    generic_risk: {
      severity: 'HIGH',
      title: 'Exposed SSH service',
      description: 'SSH service accessible, ensure strong authentication',
      confidence: 'HIGH',
      ai_risk_score: 0.7
    }
  },
  'ftp': {
    products: ['vsftpd', 'proftpd'],
    confidence: 'MEDIUM',
    generic_risk: {
      severity: 'HIGH',
      title: 'Exposed FTP service',
      description: 'FTP may transmit credentials in plain text',
      confidence: 'HIGH',
      ai_risk_score: 0.8
    }
  },
  'dns': {
    products: ['bind', 'dnsmasq', 'unbound'],
    confidence: 'LOW',
    generic_risk: {
      severity: 'MEDIUM',
      title: 'Exposed DNS service',
      description: 'DNS service accessible, potential amplification attacks',
      confidence: 'MEDIUM',
      ai_risk_score: 0.6
    }
  },
  'smtp': {
    products: ['postfix', 'exim', 'sendmail'],
    confidence: 'LOW',
    generic_risk: {
      severity: 'MEDIUM',
      title: 'Exposed SMTP service',
      description: 'Mail transfer agent accessible',
      confidence: 'MEDIUM',
      ai_risk_score: 0.5
    }
  },
  'telnet': {
    products: [],
    confidence: 'HIGH',
    generic_risk: {
      severity: 'CRITICAL',
      title: 'Telnet service detected',
      description: 'Telnet transmits credentials in plain text',
      confidence: 'HIGH',
      ai_risk_score: 0.9
    }
  },
  'snmp': {
    products: ['net-snmp'],
    confidence: 'MEDIUM',
    generic_risk: {
      severity: 'HIGH',
      title: 'Exposed SNMP service',
      description: 'SNMP may use default community strings',
      confidence: 'HIGH',
      ai_risk_score: 0.7
    }
  }
};
export const DEVICE_PORT_SIGNATURES = {
  'smartphone': {
    ports: [],
    services: [],
    description: 'Typically few open ports, may have mDNS/SSDP',
    weight: 0.6,
    ml_features: ['low_port_count', 'mobile_services']
  },
  'windows_pc': {
    ports: [135, 139, 445, 3389, 5985, 5986],
    services: ['msrpc', 'netbios-ssn', 'microsoft-ds', 'ms-wbt-server'],
    description: 'Windows SMB, RPC, RDP, WinRM',
    weight: 0.85,
    ml_features: ['windows_ports', 'smb', 'rdp']
  },
  'linux_pc': {
    ports: [22, 111, 631, 2049],
    services: ['ssh', 'rpcbind', 'ipp', 'nfs'],
    description: 'SSH, RPC, printing services',
    weight: 0.8,
    ml_features: ['linux_ports', 'ssh', 'nfs']
  },
  'iot_camera': {
    ports: [80, 443, 554, 37777, 8000],
    services: ['http', 'rtsp', 'unknown'],
    description: 'Web interface, RTSP stream, proprietary protocols',
    weight: 0.9,
    ml_features: ['camera_ports', 'rtsp', 'http']
  },
  'smart_tv': {
    ports: [8008, 8009, 9080, 1900],
    services: ['googlecast', 'upnp'],
    description: 'Google Cast, UPnP media services',
    weight: 0.8,
    ml_features: ['tv_ports', 'upnp', 'googlecast']
  },
  'router': {
    ports: [53, 67, 68, 80, 443, 161, 162],
    services: ['dns', 'dhcp', 'http', 'snmp'],
    description: 'DNS, DHCP, web admin, SNMP',
    weight: 0.9,
    ml_features: ['router_ports', 'dns', 'dhcp', 'snmp']
  },
  'printer': {
    ports: [80, 443, 515, 631, 9100],
    services: ['http', 'printer', 'ipp', 'jetdirect'],
    description: 'Web interface, printing protocols',
    weight: 0.85,
    ml_features: ['printer_ports', 'ipp', 'http']
  }
};
export const MAC_VENDOR_PATTERNS: Record<string, { vendor: string; weight: number }> = {
    '00:0c:29': { vendor: 'VMware ESXi/Workstation', weight: 0.95 },
    '00:50:56': { vendor: 'VMware ESXi', weight: 0.95 },
    '00:1c:14': { vendor: 'Dell', weight: 0.85 },
    'b8:27:eb': { vendor: 'Raspberry Pi', weight: 0.98 },
    'dc:a6:32': { vendor: 'Raspberry Pi', weight: 0.98 },
    'a4:5e:60': { vendor: 'Apple (iPhone/iPad)', weight: 0.85 },
    'ac:bc:32': { vendor: 'Apple', weight: 0.8 },
    'fc:25:3f': { vendor: 'Google', weight: 0.75 },
    '4c:66:41': { vendor: 'Samsung', weight: 0.8 },
    '00:24:be': { vendor: 'Netgear', weight: 0.8 },
    'a0:21:b7': { vendor: 'TP-Link', weight: 0.85 },
    'f8:1a:67': { vendor: 'Ubiquiti', weight: 0.8 }
};