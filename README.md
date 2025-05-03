
# Instalando dependências diretamente:
```
pip install textual
pip install netifaces
pip install dnspython
pip install python-whois
pip install requests
pip install python-Wappalyzer
pip install --upgrade setuptools
```

# Ferramentas implementadas:
- Portscan
- DNS enumeration
- WHOIS lookup
- Wappalyzer
- Subdomain enumeration

# Uso:
<video width="480" controls>
  <source src="https://youtu.be/H5qRX78FG50" type="video/mp4">
  Seu navegador não suporta a tag de vídeo.
</video>

link: https://youtu.be/H5qRX78FG50

# Perguntas e Respostas

### Além do PortScan, quais são as 5 ferramentas mais úteis para reconhecimento em um pentest?

* Shodan: motor de busca para dispositivos IoT expostos na internet, utilizado para mapear câmeras de segurança e roteadores. Caso real: botnet Mirai explorou dispositivos IoT identificados pelo Shodan. (https://www.shodan.io)

* theHarvester: coleta e-mails, subdomínios e IPs de fontes públicas, essencial para campanhas de phishing. Caso real: em 2018 foi usado para mapear endereços de e-mail de uma grande universidade antes de ataque de spear-phishing. (https://github.com/laramies/theHarvester)

* OWASP Amass: enumerador de subdomínios usando fontes passivas (logs de certificados) e ativas (bruteforce), muito usado por grandes organizações para monitorar ativos expostos (https://github.com/OWASP/Amass)

* Wappalyzer CLI: identifica tecnologias web (CMS, frameworks, bibliotecas) em sites, facilitando a seleção de exploits específicos para cada stack (https://github.com/AliasIO/Wappalyzer)

* Sublist3r: enumera subdomínios via múltiplas fontes (motores de busca, certificados), acelerando a descoberta da superfície de ataque (https://github.com/aboul3la/Sublist3r)

### Qual a diferença entre um scanner de portas SYN e um TCP Connect Scan?

SYN Scan envia apenas pacotes SYN e analisa respostas SYN-ACK ou RST sem completar o handshake TCP, gerando menos logs no alvo. Ou seja, o SYN Scan é mais furtivo e ideal quando se tem privilégios de root e se deseja minimizar detecção. Já o TCP Connect Scan usa a chamada de sistema connect() para concluir o handshake completo TCP, não requer privilégios de root, mas é facilmente detectável por IPS e logs. Dessa forma, o TCP Connect Scan é a opção quando não há acesso a raw sockets (por exemplo, em redes IPv6 sem suporte a RAW) ou sem privilégios elevados.

Referência: https://nmap.org/book/man-port-scanning-techniques.html#man-port-scanning-techniques-syn


### Como um pentester pode evitar ser detectado por sistemas de prevenção de intrusão (IPS) durante o reconhecimento?

Uma estratégia é aplicar atrasos entre o envio de pacotes (scan delay), mantendo a taxa de sondagem abaixo do limiar que acionaria alarmes, o que, no entanto, estende significativamente a duração do processo. Outra técnica é a fragmentação de pacotes em pedaços menores, confundindo os mecanismos de remontagem do IPS, mas gerando overhead extra e aumentando o risco de perda de fragmentos. O pentester também pode dispersar os alvos, limitando o número de hosts escaneados simultaneamente, para evitar que um único IP receba tráfego em volume elevado; isso torna o reconhecimento mais demorado e exige múltiplas sessões. O uso de decoys insere endereços falsos junto ao IP real, dificultando a identificação da origem, porém multiplica a quantidade de tráfego e pode chamar atenção se mal configurado. Com o idle scan, a varredura é feita por meio de um “zumbi” (host intermediário), ocultando o IP do atacante; o método é muito furtivo, mas depende de encontrar um zumbi vulnerável e introduz complexidade e latência adicionais. Por fim, encapsular o tráfego em proxies, VPNs ou na rede Tor esconde o endereço real do pentester, porém adiciona alta latência e aumenta as chances de bloqueio ou perda de pacotes.

referencias: 
- https://nmap.org/book/man-performance.html
- https://nmap.org/book/man-port-scanning-techniques.html
- https://nmap.org/book/man-port-scanning-basics.html