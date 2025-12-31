

deploy:
	modprobe openvswitch
	docker compose up -d
clean:
	docker compose down
