install:
	python -m pip install -r requirements.txt

run-dummy:
	python lab/dummy_login_server.py

list:
	python -m auth_traffic_auditor.cli --list

test-password:
	python tests/run_password_test.py
