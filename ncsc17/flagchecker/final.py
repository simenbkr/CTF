import angr

win = 0x400ded
lose = [0x400702 + i * 50 for i in range(36)]
p = angr.Project('checker')

st = p.factory.full_init_state(args=['./checker'])

def char(state, c):
    return state.se.And(c <= '~', c >= ' ')


for i in range(256):
    c = st.posix.files[0].read_from(1)
    st.se.add(char(st, c))


st.posix.files[0].seek(0)
st.posix.files[0].length = 256


fgetsaddr = 0x4006bb


ex = p.surveyors.Explorer(find=(win,), avoid=lose)
ex.run()


#print ex
#print dir(ex.found[0].state)

print ex._f.state.posix.dumps(0)


