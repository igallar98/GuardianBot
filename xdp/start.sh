
sudo sh -c "ulimit -c unlimited"
sudo sh -c "exec su ./xdp_loader --skb-mode --dev wlp4s0 --force --progsec xdp_pass"
sudo sh -c "exec su ./xdp_stats --dev wlp4s0"
