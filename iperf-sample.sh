for i in {1..50}; do iperf -u -c 10.0.0.3 -b 10m -t 20& sleep 1; done
