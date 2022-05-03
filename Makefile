install:
	pip3 install --upgrade pip &&\
		pip3 install -r requirements.txt &&\
		git clone https://github.com/secdev/scapy.git &&\
		cd scapy &&\
		sudo python3 setup.py install


format:
	black *.py

lint:
	pylint --disable=R,C csr_generator.py

#test:
#	python3 -m pythest -vv --cov=fire  csr_generator.py
