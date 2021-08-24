package intcodeghidra;

import java.io.IOError;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class IntcodeGhidraLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {

		// TODO: Name the loader. This name must match the name of the loader in the
		// .opinion files.

		return "Intcode Text";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		BinaryReader reader = new BinaryReader(provider, true);
		long len = Math.min(reader.length(), 100L);
		for (long i = 0; i < len; i++) {
			// Match /[-,\s0-9]*/
			byte b = reader.readNextByte();
			switch (b) {
			case '-':
			case ',':
			case ' ':
			case '\r':
			case '\n':
				break;
			default:
				if (b > 0 && b - '0' < 10)
					break;
				return new ArrayList<>();
			}
		}

		return List.of(new LoadSpec(this, 0, new LanguageCompilerSpecPair("intcode:LE:64:default", "default"), true));
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		try {
			FlatProgramAPI api = new FlatProgramAPI(program, monitor);
			BinaryReader reader = new BinaryReader(provider, true);
			ArrayList<Long> data = new ArrayList<>();

			long scalar = 0L;
			boolean inNum = false;
			boolean neg = false;
			for (int i = 0; i < reader.length(); i++) {
				// Match /[-0-9,\s]*/
				byte b = reader.readNextByte();
				switch (b) {
				case '-':
					assert !inNum;
					assert !neg;
					neg = true;
					break;
				case ',':
					assert inNum;
					inNum = false;
					data.add(scalar);
					scalar = 0;
					break;
				case ' ':
				case '\r':
				case '\n':
					break;
				default:
					assert b >= '0' && b <= '9';
					inNum = true;
					scalar *= 10;
					scalar += b - '0';
					if (neg) {
						scalar *= -1;
						neg = false;
					}
				}
			}
			if (inNum)
				data.add(scalar);

			Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
			Memory mem = program.getMemory();
			MemoryBlock block = mem.createInitializedBlock("ram", start, data.size() * 8, (byte) 0, monitor, false);
			block.setPermissions(true, true, true); // rwx

			for (int i = 0; i < data.size(); i++) {
				mem.setLong(start.add(i * 8), data.get(i));
			}

			api.createLabel(start, "entry", true, SourceType.IMPORTED);
			api.addEntryPoint(start);
			
			// Now we need to create a function in order to properly assign the storage as void.
			Function entry = api.createFunction(start, "entry");
			if (entry == null) throw new Exception("Unable to create entrypoint");
			entry.setReturn(DataType.VOID, VariableStorage.VOID_STORAGE, SourceType.IMPORTED);
			entry.replaceParameters(FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.IMPORTED);
		} catch (Exception e) {
			throw new IOError(e);
		}
	}
}
