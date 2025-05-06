# bpfdoor-detection

### Yara Script를 이용한 탐지
yara -r bpfdoor_rules.yar / 2>/dev/null

### python script를 이용한 탐지
python3 ./bpfdoor-scan.py /

### Linux 환경에서 BPF filter가 삽입된 프로세스 확인
sudo ss -0pb
