$TTL    604800
ejemplo.com.       IN      SOA     ns1  admin (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                         2419200        ; Expire 
                         604800 )       ; Negative Cache TTL

; Servidores de nombre
@       IN      NS      PC11.ejemplo.com.
	IN	NS	PC12.ejemplo.com.

; Estaciones de trabajo de la red 192.168.81.0/24
PC1     IN      A       192.168.81.1
PC2     IN      A       192.168.81.2
PC3     IN      A       192.168.81.3
PC4     IN      A       192.168.81.4
PC5     IN      A       192.168.81.5
PC6     IN      A       192.168.81.6
PC7     IN      A       192.168.81.7
PC8     IN      A       192.168.81.8
PC9     IN      A       192.168.81.9

; Servidor DHCP + Router. debian1-pruebas
PC10	IN	A	192.168.81.10
	IN	A	192.168.82.10

; Servidores DNS
PC11	IN	A	192.168.81.11
PC12	IN	A	192.168.81.12

; Servidores de la red 192.168.82.0/24
PC14	IN	A	192.168.82.1
PC15	IN	A	192.168.82.1
