# Cerberus


A custom implementation of the ping and traceroute utility developed in C. This project was created for learning more about raw sockets and how IPV4 and ICMP packets work.

## Build

Before building and running ping and traceroute, ensure your operating system is Linux-based system, has gcc and make installed. You also need admin priveleges as this project opens raw sockets. To build the executables follow the below steps,

    $ git clone https://github.com/shackleb0lt/cerberus.git
    $ cd cerberus
    $ make release

The ```ping``` and ```tracert``` binaries will be saved in the generate ```bld/``` folder. You need to modify the binary permissions to allow them to create raw sockets, below are the steps for same,

    $ sudo setcap cap_net_raw+ep bld/ping
    $ sudo setcap cap_net_raw+ep bld/tracert

Alternatively you can run the ```run.sh``` bash script to avoid repeated execution of above commands.

See [ping](#usage) and [traceroute](#usage-1) sections for usage of these binaries.


## ping

Ping is a network utility used to test connectivity and measure round-trip time between your computer and a target host. It sends ICMP Echo Request packets and waits for ICMP Echo Reply packets. It is generally invoked as ```ping <hostname or IP addr>```, where hostname can be domain name like ```google.com``` or a IP address like ```1.1.1.1```.

### Working
Execution flow of ping is as follows,
- Resolves the destination hostname to an IPv4 address
- Finds the IPv4 address of the host machine for source
- Creates a raw socket and configures socket options to allow header inclusion
- Drops the root priveleges
- Constructs a packet by filling IPv4 and ICMP header fields manually
- Sends the packet and waits for a ICMP Echo response in a loop
- If response is not received within a certain time  the packet is marked as lost
- If an error response is received, decode and print to the screen.
- The loop exits on a signal interrupts or if specified number of packets are sent

### Usage

Below are the parameters that can be passed to this utility,

    Usage:
    ping [options] <hostname or IPv4 address>

    Options:
    -c <count>         Stop after <count> ping packets 
    -i <interval>      milliseconds between each packet
    -t <ttl value>     configure time to live (1-64)
    -s <size>          configure icmp data payload size
    -q                 quiet output
    -v                 verbose output
    -h                 show usage and exit

Sample command to check reachability of an IP address,

    $ ./bld/ping github.com
    $ ./bld/ping -c 10 github.com
    $ ./bld/ping -c 100 -q github.com
    $ ./bld/ping -c 100 -i 10 github.com

## traceroute

Traceroute maps the path packets take to a target host by sending packets with gradually increasing TTL (Time to Live) values. It shows each hop (router) along the way.

### Working 

This follows similar steps to ping, ony difference is that outgoing packets start with a TTL value of 1 until a ICMP Echo Reply is received or until the configured max hop limit is reached.
If the ICMP packets TTL expires enroute then we receive ICMP Time Exceeded code from a router along the way.

### Usage

    Usage:
    tracert [options] <hostname or IPv4 address>

    Options:
    -m <num>           Max number of hops
    -h                 show usage and exit

Sample command to trace the route,

    ./bld/tracert 1.1.1.1
    ./bld/tracert -m 2 1.1.1.1

## Future Enhancement Ideas

- Allow configuring number of packets being sent
- Resolve public IP address to hostname 
- Allow option for UDP based pinging