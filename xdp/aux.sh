sudo mount -t bpf bpf /sys/fs/bpf/
ulimit -l unlimited
sudo ./xdp_loader --auto-mode --dev $(echo | route | grep '^default' | grep -o '[^ ]*$') --force --progsec xdp_pass
sudo ./xdp_stats --dev $(echo | route | grep '^default' | grep -o '[^ ]*$') &

cd ../interface
sudo python3 run.py

