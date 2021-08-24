# python3 ./gen_sla.py > ./data/languages/intcode_gen.sinc

import itertools


def gen_header():
    # position
    for reg in "bcd":
        yield f"s{reg}p: [scaled] is s{reg} [ scaled=s{reg}*8; ] {{ export *:8 scaled; }}"

    # relative
    for reg in "bcd":
        yield f"s{reg}r: [SP + scaled] is s{reg} & SP [ scaled=s{reg}*8; ] {{ local out:8 = SP + scaled; export *:8 out; }}"

    # immediate
    for reg in "bc":
        yield f's{reg}i: "#"^s{reg} is s{reg} {{ local out:8 = s{reg}; export out; }}'

    # jump
    # yield "jcp: scp*8 is sc & scp { local dest:8 = scp*8; export *:8 dest; }"
    # yield "jcr: scr*8 is sc & scr { local dest:8 = scr*8; export *:8 dest; }"
    # yield "jci: dest is sc [ dest=sc*8; ] { local dest2:8 = sc*8; export *:8 dest2; }"

    # offset
    for reg in "bc":
        yield f"o{reg}p: s{reg}p*8 is s{reg} & s{reg}p {{ local out:8 = s{reg}p*8; export out; }}"
        yield f"o{reg}r: s{reg}r*8 is s{reg} & s{reg}r {{ local out:8 = s{reg}r*8; export out; }}"
        yield f'o{reg}i: "#"^scaled is s{reg} [ scaled=s{reg}*8; ] {{ local out:8 = scaled; export out; }}'

    # jump
    yield "jcp: scaled is sc [ scaled=sc*8; ] { export *:8 scaled; }"


def gen_constructors(code, mnemonic, params, pcode):
    param_modes = []
    for i, param_type in enumerate(params):
        reg = chr(i+ord("b"))

        if param_type == "j" or param_type == "o":
            access_type = "o"
        else:
            access_type = "s"  # signed

        pos = (0, f"{access_type}{reg}p")
        imm = (1, f"{access_type}{reg}i")
        rel = (2, f"{access_type}{reg}r")

        if param_type == "r" or param_type == "o":
            param_modes.append([pos, rel, imm])
        elif param_type == "w" or param_type == "j":
            param_modes.append([pos, rel])
        else:
            print("Invalid parameter type")
            assert False

    for params in itertools.product(*param_modes):
        codes = [str(p[0]) for p in params]
        symbols = [p[1] for p in params]
        mode_str = "".join(reversed(codes))

        header = f":{mnemonic}"
        display = ",".join(f" {sym}" for sym in symbols)
        bit_pattern = f" is op={mode_str}{code:02} & sign=0"
        bit_pattern += "".join(f"; {sym}" for sym in symbols)
        semantics = f" {{ {pcode.format(*symbols)} }}"
        constructor = header + display + bit_pattern + semantics

        yield constructor


def gen_jump_imm():
    for val, comp_zero, op in [("true ", "!=", 5), ("false", "==", 6)]:
        yield f":jump_if_{val} sbp, jcp is op=100{op} & sign=0; sbp; jcp {{ if (sbp {comp_zero} 0) goto jcp; }}"
        yield f":jump_if_{val} sbr, jcp is op=120{op} & sign=0; sbr; jcp {{ if (sbr {comp_zero} 0) goto jcp; }}"
        yield f":jump_if_{val} sbi, jcp is op=110{op} & sign=0; sbi; jcp {{ if (sbi {comp_zero} 0) goto jcp; }}"

# def gen_offset():
#     yield ":offset sbp*8 is sb & sbp { SP = SP + sbp*8; }"
#     yield ":offset sbr*8 is sb & sbr { SP = SP + sbr*8; }"
#     yield ":offset rel is sb [ rel=sb*8; ] { SP = SP + rel; }"


if __name__ == "__main__":
    print("# generated by gen_sla.py\n")

    # [(opcode, mnemonic, params (read/write/jump/offset), is_jump, pcode)]
    ops = [
        (1, "add", "rrw", "{2} = {0} + {1};"),
        (2, "mul", "rrw", "{2} = {0} * {1};"),
        (3, "input ", "w", "{0} = input();"),
        (4, "output", "r", "output({0});"),
        (5, "jump_if_true ", "rj",
         "if ({0} == 0) goto inst_next; goto [{1}];"),
        (6, "jump_if_false", "rj",
         "if ({0} != 0) goto inst_next; goto [{1}];"),
        (7, "less_than", "rrw", "{2} = sext({0} s< {1});"),
        (8, "equals   ", "rrw", "{2} = sext({0} == {1});"),
        (9, "offset", "o", "SP = SP + {0};"),
        (99, "halt", "", "halt(); goto inst_start;"),
    ]

    for l in gen_header():
        print(l)
    print()
    for op in ops:
        for l in gen_constructors(*op):
            print(l)
    for l in gen_jump_imm():
        print(l)