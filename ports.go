package main

import "fmt"

// Well-known services, offered in the "add port" list and used to name the
// rows of the table (technical names, so in English in both languages).
type known struct {
	Kind string
	Port int
	Name string
}

var wellKnown = []known{
	{KindTCP, 3389, "Remote Desktop"},
	{KindUDP, 3389, "Remote Desktop (UDP)"},
	{KindTCP, 22, "SSH / SFTP"},
	{KindTCP, 80, "Web (HTTP)"},
	{KindTCP, 443, "Web (HTTPS)"},
	{KindUDP, 443, "Web (HTTP/3, QUIC)"},
	{KindTCP, 8080, "Web (HTTP 8080)"},
	{KindTCP, 8443, "Web (HTTPS 8443)"},
	{KindTCP, 21, "FTP"},
	{KindTCP, 990, "FTPS"},
	{KindTCP, 25, "SMTP"},
	{KindTCP, 465, "SMTP (SSL)"},
	{KindTCP, 587, "SMTP (Submission)"},
	{KindTCP, 110, "POP3"},
	{KindTCP, 995, "POP3 (SSL)"},
	{KindTCP, 143, "IMAP"},
	{KindTCP, 993, "IMAP (SSL)"},
	{KindTCP, 53, "DNS"},
	{KindUDP, 53, "DNS"},
	{KindTCP, 445, "File Sharing (SMB)"},
	{KindTCP, 1433, "SQL Server"},
	{KindTCP, 1521, "Oracle"},
	{KindTCP, 3306, "MySQL / MariaDB"},
	{KindTCP, 5432, "PostgreSQL"},
	{KindTCP, 27017, "MongoDB"},
	{KindTCP, 6379, "Redis"},
	{KindTCP, 9200, "Elasticsearch"},
	{KindTCP, 5985, "WinRM"},
	{KindTCP, 5986, "WinRM (HTTPS)"},
	{KindTCP, 5900, "VNC"},
	{KindUDP, 1194, "OpenVPN"},
	{KindTCP, 1194, "OpenVPN (TCP)"},
	{KindUDP, 51820, "WireGuard"},
	{KindUDP, 500, "IPsec VPN (IKE)"},
	{KindUDP, 4500, "IPsec VPN (NAT-T)"},
	{KindTCP, 1723, "PPTP VPN"},
	{KindUDP, 1701, "L2TP VPN"},
	{KindUDP, 5060, "SIP (VoIP)"},
	{KindTCP, 1883, "MQTT"},
	{KindTCP, 808, "Revit Server"},
	{KindTCP, 25565, "Minecraft"},
}

func knownName(kind string, port int) string {
	for _, k := range wellKnown {
		if k.Kind == kind && k.Port == port {
			return k.Name
		}
	}
	return ""
}

// knownLabel: a line of the "add port" list, e.g. "TCP 3389   Remote Desktop".
func knownLabel(k known) string {
	return fmt.Sprintf("%s %d   %s", k.Kind, k.Port, k.Name)
}
