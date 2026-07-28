.PHONY: test lint lint-production serve stop smoke

OPENRESTY ?= openresty

# 运行纯逻辑 + handler 集成测试（只需 luajit，无需 OpenResty）
test:
	@luajit spec/run.lua

# 配置体检：静态检查运维维护的 conf/waf_rules.lua（默认空白名单、全拒绝）
lint:
	@luajit scripts/check_rules.lua

# 兼容旧命令；简化版与 lint 使用同一套检查。
lint-production:
	@luajit scripts/check_rules.lua --production conf/waf_rules.lua

# 启动 WAF（需要本机已安装 OpenResty）
serve:
	@mkdir -p logs
	@$(OPENRESTY) -p "$(CURDIR)/" -c conf/nginx.conf
	@echo "WAF listening on http://127.0.0.1:8080"

stop:
	@$(OPENRESTY) -p "$(CURDIR)/" -c conf/nginx.conf -s stop

# 对显式加载的知识库示例规则发冒烟请求；生产应使用运维规则对应的验收用例
smoke:
	@bash scripts/smoke.sh
