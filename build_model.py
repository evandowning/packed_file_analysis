import pefile
pe = pefile.PE("./0f7e9424d5bc483173a45a9a9ce6e961812cbc9a194e72a584a51583a2d4a007")

# Get bytes from entry point
ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
np.frombuffer(pe.get_data(ep, length=1024), np.uint8)

# Get bytes from various sections
for section in pe.sections:
    print('name:{} begin_virtual_addr: {}'.format(section.Name.decode('utf-8'), hex(section.VirtualAddress)))

    # Convert to Numpy array directly
    np_array = np.frombuffer(pe.get_data(pe.sections[1].VirtualAddress, length=16), np.uint8)
