sudo mount -t bpf bpf /sys/fs/bpf/
ulimit -l unlimited
sudo ./xdp_loader --auto-mode --dev $(echo | route | grep '^default' | grep -o '[^ ]*$' | head -n 1) --force --progsec xdp_pass
sudo ./xdp_stats --dev $(echo | route | grep '^default' | grep -o '[^ ]*$' | head -n 1) &

cd ../interface
sudo python3 run.py

