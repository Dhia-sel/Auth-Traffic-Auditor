from auth_traffic_auditor.attacks.password_spraying import PasswordSprayingModule

m = PasswordSprayingModule()
res = m.run('http://127.0.0.1:5000', passwords=['azerty'], usernames=['admin'], delay=0, timeout=1)
print(res)
