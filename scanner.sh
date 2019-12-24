range=$1

hosts=$(nmap -sP $range | grep 'report for' | cut -d ' ' -f 5)

for host in $hosts
do
    clear
    echo 'Starting work for $host'

    ports=$(sudo masscan --wait 5 -p1-65535 -e tap0 --router-ip=10.11.0.1 --rate 5000 $host | cut -d ' ' -f 4 | cut -d '/' -f 1 | sort -n | paste -sd ',')
    clear
    echo 'Masscan for $host done'
    mkdir -p $host
    nmap -sV -Pn -p$ports -v -n -oA $host/nmap $host
done