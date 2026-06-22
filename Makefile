.PHONY: test serve stop smoke

OPENRESTY ?= openresty

# 运行纯逻辑 + handler 集成测试（只需 luajit，无需 OpenResty）
test:
	@luajit spec/run.lua

# 启动 WAF（需要本机已安装 OpenResty）
serve:
	@mkdir -p logs
	@$(OPENRESTY) -p "$(CURDIR)/" -c conf/nginx.conf
	@echo "WAF listening on http://127.0.0.1:8080"

stop:
	@$(OPENRESTY) -p "$(CURDIR)/" -c conf/nginx.conf -s stop

# 对运行中的 WAF 发冒烟请求，验证放行/拦截
smoke:
	@bash scripts/smoke.sh
