long values[nr_cpus];

ret = bpf_map_lookup_elem(map_fd, &next_key, values);

for (i = 0; i < nr_cpus; i++) {
    sum += values[i];
}