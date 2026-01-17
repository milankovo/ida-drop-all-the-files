import idaapi
for k, v in globals().items():
    print(f"{k}: {type(v)}")
    print(f"{v}")

print(idaapi.get_screen_ea())
1/0