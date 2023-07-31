File looks simple enough to solve with symbolic execution. The underlined instruction will give angr problems without using Unicorn however.
![image](https://github.com/Leodler/ctf-writeups/assets/48812008/f5ef36f6-218e-4304-86dc-5ea8f8cfb9de)

(not worrying about different base addressess between angr and Binary Ninja, we can replace the last 4 characters with our address from Binary Ninja)

Our find address is at ```0x12c7``` and our avoid address is at ```0x12d5```

We can throw together a script to explore until we reach our desired address
```python
import angr
import claripy

p = angr.Project('./chall')

state = p.factory.full_init_state(
    args=['./chall'],
    add_options=angr.options.unicorn,
    stdin=claripy.BVS('stdin', 0x40*8)
)

simgr = p.factory.simulation_manager(state)

simgr.explore(find=0x4012c7, avoid=0x4012d5)

print(simgr.found[0].posix.dumps(0))
```
```lucas@DESKTOP-2IE8M49:~/zeropts$ python3 solve.py 
WARNING  | 2023-07-17 11:33:22,628 | angr.simos.simos | stdin is constrained to 64 bytes (has_end=True). If you are only providing the first 64 bytes instead of the entire stdin, please use stdin=SimFileStream(name='stdin', content=your_first_n_bytes, has_end=False).
b"zer0pts{d0n'7_4lw4y5_7ru57_d3c0mp1l3r}\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"```
