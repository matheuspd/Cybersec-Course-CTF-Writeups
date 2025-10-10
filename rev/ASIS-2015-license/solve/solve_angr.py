import angr
import claripy

def main():
    p = angr.Project("license", load_options={'auto_load_libs': False})

    # Cria um estado em branco
    state = p.factory.blank_state()

    # BCria o arquivo de licensa com o nome original
    license_name = "_a\nb\tc_"

    # Esse é o arquivo de licença
    # Analisando o binário, descobrimos que o arquivo deve conter 5 linhas
    # no total e cada linha deve conter 6 chars. Sem essas informações, o angr 
    # poderia funcionar, mas criaria muitos mais caminhos e demoraria bem mais tempo.
    
    bytestring = None
    for i in range(5):
        line = [ ]
        for j in range(6):
            line.append(claripy.BVS('license_file_byte_%d_%d' % (i, j), 8))
            state.add_constraints(line[-1] != b'\n')
        if bytestring is None:
            bytestring = claripy.Concat(*line)
        else:
            bytestring = bytestring.concat(claripy.BVV(b'\n'), *line)

    license_file = angr.storage.file.SimFile(license_name, bytestring)
    state.fs.insert(license_name, license_file)

    simgr = p.factory.simulation_manager(state)

    simgr.explore(
                find=(0x400e93, ),
                avoid=(0x400bb1, 0x400b8f, 0x400b6d, 0x400a85,
                       0x400ebf, 0x400a59)
            )

    # Um caminho será achado
    found = simgr.found[0]
    rsp = found.regs.rsp
    flag_addr = rsp + 0x278 - 0xd8 # Valores retirados do IDA
    # Simulamos uma chamado inline para a função strlen para encontrar o tamanho
    # da flag
    FAKE_ADDR = 0x100000
    strlen = lambda state, arguments: \
        angr.SIM_PROCEDURES['libc']['strlen'](p, FAKE_ADDR).execute(
            state, arguments=arguments
        )
    flag_length = strlen(found, arguments=[flag_addr]).ret_expr
    # No caso de o arquivo não terminar em NULL, recebemos o menor tamanho possível
    flag_length_int = min(found.solver.eval_upto(flag_length, 3))
    # Encontrando a flag!
    flag_int = found.solver.eval(found.memory.load(flag_addr, flag_length_int))
    flag = bytes.fromhex(hex(flag_int)[2:])
    return flag

if __name__ == '__main__':
    print(main())
