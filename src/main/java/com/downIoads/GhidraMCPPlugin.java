package com.downIoads;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.Analyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StringUTF8DataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.TerminatedUnicodeDataType;
import ghidra.program.model.data.UnicodeDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import java.math.BigInteger;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.options.Options;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblyException;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.FrontEndTool;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoaderService;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.CompilerSpecDescription;
import ghidra.program.util.DefaultLanguageService;
import ghidra.app.services.GoToService;
import ghidra.program.util.ProgramSelection;
import generic.stl.Pair;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.lang.ref.WeakReference;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;

    private final Map<String, AnalysisJob> analysisJobs = new ConcurrentHashMap<>();
    private final AtomicLong analysisJobCounter = new AtomicLong(1);

    private final java.util.TreeSet<String> registeredEndpoints = new java.util.TreeSet<>();

    private void registerContext(String path, com.sun.net.httpserver.HttpHandler handler) {
        registeredEndpoints.add(path);
        server.createContext(path, handler);
    }

    private interface JsonSupplier {
        Object get() throws Exception;
    }

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }
        registeredEndpoints.clear();

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Each listing endpoint uses offset & limit from query params:
        registerContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        registerContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        registerContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        registerContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        registerContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
        });

        registerContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        registerContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        registerContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        registerContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        registerContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        registerContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        registerContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements
        
        registerContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        registerContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        registerContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        registerContext("/list_functions", exchange -> {
            sendResponse(exchange, listFunctions());
        });

        registerContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        registerContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        registerContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        registerContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        registerContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        registerContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        registerContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        registerContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        registerContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        registerContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        registerContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        registerContext("/get_address_info", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, getAddressInfo(qparams.get("address")));
        });

        registerContext("/get_instruction_at", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, getInstructionAt(qparams.get("address")));
        });

        registerContext("/get_instructions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, getInstructions(
                qparams.get("start"),
                qparams.get("end"),
                parseIntOrDefault(qparams.get("limit"), 100)
            ));
        });

        registerContext("/get_data_at", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, getDataAt(qparams.get("address")));
        });

        registerContext("/get_function_details", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, getFunctionDetails(qparams.get("address"), qparams.get("name")));
        });

        registerContext("/list_function_variables", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, listFunctionVariables(qparams.get("address"), qparams.get("name")));
        });

        registerContext("/list_symbols", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, listSymbols(qparams));
        });

        registerContext("/search_symbols", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, listSymbols(qparams));
        });

        registerContext("/get_symbol", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, getSymbol(qparams.get("address"), qparams.get("name")));
        });

        registerContext("/list_comments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, listComments(qparams));
        });

        registerContext("/list_bookmarks", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, listBookmarks(qparams));
        });

        registerContext("/get_references", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, getReferences(qparams));
        });

        registerContext("/set_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setComment(params));
        });

        registerContext("/set_label", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setLabel(params));
        });

        registerContext("/delete_label", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, deleteLabel(params));
        });

        registerContext("/set_primary_symbol", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setPrimarySymbol(params));
        });

        registerContext("/create_namespace", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createNamespace(params));
        });

        registerContext("/rename_namespace", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, renameNamespace(params));
        });

        registerContext("/create_reference", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createReference(params));
        });

        registerContext("/delete_reference", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, deleteReference(params));
        });

        registerContext("/set_reference_primary", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setReferencePrimary(params));
        });

        registerContext("/create_memory_reference", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createReference(params));
        });

        registerContext("/create_stack_reference", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createStackReference(params));
        });

        registerContext("/create_external_reference", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createExternalReference(params));
        });

        registerContext("/list_data_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, listDataTypes(qparams));
        });

        registerContext("/search_data_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, listDataTypes(qparams));
        });

        registerContext("/get_data_type", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, getDataType(qparams.get("path")));
        });

        registerContext("/get_struct_layout", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, getStructLayout(qparams.get("path")));
        });

        registerContext("/get_enum_values", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, getEnumValues(qparams.get("path")));
        });

        registerContext("/get_typedef_target", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, getTypedefTarget(qparams.get("path")));
        });

        registerContext("/apply_data_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, applyDataTypeAt(params));
        });

        registerContext("/create_struct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createStruct(params));
        });

        registerContext("/delete_struct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, deleteDataType(params));
        });

        registerContext("/rename_data_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, renameDataType(params));
        });

        registerContext("/add_struct_field", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, addStructField(params));
        });

        registerContext("/rename_struct_field", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, renameStructField(params));
        });

        registerContext("/set_struct_field_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setStructFieldType(params));
        });

        registerContext("/delete_struct_field", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, deleteStructField(params));
        });

        registerContext("/create_enum", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createEnum(params));
        });

        registerContext("/set_enum_value", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setEnumValue(params));
        });

        registerContext("/create_typedef", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createTypedef(params));
        });

        registerContext("/create_pointer_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createPointerType(params));
        });

        registerContext("/create_array_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createArrayType(params));
        });

        registerContext("/create_function_definition_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createFunctionDefinitionType(params));
        });

        registerContext("/set_function_name", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setFunctionName(params));
        });

        registerContext("/set_function_return_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setFunctionReturnType(params));
        });

        registerContext("/set_function_calling_convention", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setFunctionCallingConvention(params));
        });

        registerContext("/set_function_no_return", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setFunctionFlag(params, "no_return"));
        });

        registerContext("/set_function_inline", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setFunctionFlag(params, "inline"));
        });

        registerContext("/set_function_varargs", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setFunctionFlag(params, "varargs"));
        });

        registerContext("/set_function_thunk", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setFunctionThunk(params));
        });

        registerContext("/set_function_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setFunctionComment(params));
        });

        registerContext("/list_parameters", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, listParameters(qparams));
        });

        registerContext("/rename_parameter", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, renameParameter(params));
        });

        registerContext("/set_parameter_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setParameterType(params));
        });

        registerContext("/set_parameter_storage", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setParameterStorage(params));
        });

        registerContext("/add_parameter", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, addParameter(params));
        });

        registerContext("/remove_parameter", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, removeParameter(params));
        });

        registerContext("/reorder_parameters", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, reorderParameters(params));
        });

        registerContext("/rename_local_variable_by_storage", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, renameVariableByStorage(params));
        });

        registerContext("/set_local_variable_type_by_storage", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setVariableTypeByStorage(params));
        });

        registerContext("/create_stack_variable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createStackVariable(params));
        });

        registerContext("/delete_stack_variable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, deleteStackVariable(params));
        });

        registerContext("/set_stack_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setStackVariableType(params));
        });

        // -------- Write-capable / advanced endpoints (added) -------------------

        registerContext("/read_bytes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int length = parseIntOrDefault(qparams.get("length"), 16);
            sendResponse(exchange, readBytes(address, length));
        });

        registerContext("/write_bytes", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, writeBytes(params.get("address"), params.get("hex")));
        });

        registerContext("/find_bytes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String start = qparams.get("start");
            String hex   = qparams.get("hex");
            int limit    = parseIntOrDefault(qparams.get("limit"), 20);
            sendResponse(exchange, findBytes(start, hex, limit));
        });

        registerContext("/clear_listing", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, clearListing(params.get("start"), params.get("end")));
        });

        registerContext("/disassemble", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, disassembleAt(params.get("address")));
        });

        registerContext("/set_tmode", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setTMode(params.get("address"), params.get("value")));
        });

        registerContext("/set_tmode_range", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setTModeRange(params.get("start"), params.get("end"), params.get("value")));
        });

        registerContext("/propagate_ldr_pc_refs", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, propagateLdrPcRefs(params));
        });

        registerContext("/create_thumb_function_from_pointer", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createFunctionFromPointer(params));
        });

        registerContext("/scan_thumb_pointer_table", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, scanThumbPointerTable(params));
        });

        registerContext("/create_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createFunctionAt(params.get("address"), params.get("name")));
        });

        registerContext("/delete_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, deleteFunctionAt(params.get("address")));
        });

        registerContext("/create_label", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createLabel(params.get("address"), params.get("name")));
        });

        registerContext("/create_data", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createData(params.get("address"), params.get("type"),
                                              parseIntOrDefault(params.get("count"), 1)));
        });

        registerContext("/analyze", exchange -> {
            sendResponse(exchange, analyzeAll());
        });

        registerContext("/set_image_base", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setImageBase(params.get("address")));
        });

        registerContext("/create_initialized_block", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createInitializedBlock(
                params.get("name"),
                params.get("address"),
                params.get("hex"),
                params.get("read"),
                params.get("write"),
                params.get("execute")
            ));
        });

        registerContext("/create_uninitialized_block", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createUninitializedBlock(
                params.get("name"),
                params.get("address"),
                parseLongOrDefault(params.get("size"), -1),
                params.get("read"),
                params.get("write"),
                params.get("execute")
            ));
        });

        registerContext("/remove_memory_block", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, removeMemoryBlock(params.get("name"), params.get("address")));
        });

        registerContext("/set_block_permissions", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setBlockPermissions(
                params.get("name"),
                params.get("address"),
                params.get("read"),
                params.get("write"),
                params.get("execute")
            ));
        });

        registerContext("/create_function_range", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createFunctionRange(params));
        });

        registerContext("/set_function_body", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setFunctionBody(params));
        });

        registerContext("/add_function_body_range", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, addFunctionBodyRange(params));
        });

        registerContext("/remove_function_body_range", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, removeFunctionBodyRange(params));
        });

        registerContext("/repair_function_body", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, repairFunctionBody(params));
        });

        registerContext("/create_union", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createUnion(params));
        });

        registerContext("/delete_union", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, deleteUnion(params));
        });

        registerContext("/add_union_field", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, addUnionField(params));
        });

        registerContext("/rename_union_field", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, renameUnionField(params));
        });

        registerContext("/set_union_field_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setUnionFieldType(params));
        });

        registerContext("/delete_union_field", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, deleteUnionField(params));
        });

        registerContext("/clear_data", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, clearData(params));
        });

        registerContext("/create_string", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createString(params));
        });

        registerContext("/create_array", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createArrayAt(params));
        });

        registerContext("/program_info", exchange -> {
            sendResponse(exchange, programInfo());
        });

        registerContext("/list_analyzers", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, listAnalyzers(qparams));
        });

        registerContext("/get_analyzer_options", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, getAnalyzerOptions(qparams));
        });

        registerContext("/set_analyzer_option", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setAnalyzerOption(params));
        });

        registerContext("/enable_analyzer", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setAnalyzerEnabled(params, true));
        });

        registerContext("/disable_analyzer", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setAnalyzerEnabled(params, false));
        });

        registerContext("/run_analyzer", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, runAnalyzer(params));
        });

        registerContext("/analyze_range", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, analyzeRange(params));
        });

        registerContext("/analyze_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, analyzeFunction(params));
        });

        registerContext("/get_analysis_status", exchange -> {
            sendResponse(exchange, getAnalysisStatus());
        });

        registerContext("/get_analysis_log", exchange -> {
            sendResponse(exchange, getAnalysisLog());
        });

        registerContext("/list_undefined_ranges", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, listUndefinedRanges(qparams, false));
        });

        registerContext("/list_executable_undefined_ranges", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, listUndefinedRanges(qparams, true));
        });

        registerContext("/find_possible_functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, findPossibleFunctions(qparams));
        });

        // ---------- Discovery helpers (pointer/jump tables, strings) ----------
        registerContext("/find_pointer_tables", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, findPointerTables(qparams));
        });

        registerContext("/find_jump_tables", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, findJumpTables(qparams));
        });

        registerContext("/find_ascii_strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, findAsciiStrings(qparams, false));
        });

        registerContext("/find_utf16_strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, findAsciiStrings(qparams, true));
        });

        // ---------- Program lifecycle ----------
        registerContext("/list_open_programs", exchange -> {
            sendResponse(exchange, listOpenPrograms());
        });
        registerContext("/select_program", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, selectProgram(params));
        });
        registerContext("/save_program", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, saveProgram(params));
        });
        registerContext("/close_program", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, closeProgram(params));
        });
        registerContext("/import_file", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, importFile(params));
        });
        registerContext("/open_program", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, openProgram(params));
        });

        // ---------- Exports ----------
        registerContext("/export_bytes", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, exportBytes(params));
        });
        registerContext("/export_patched_binary", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, exportPatchedBinary(params));
        });
        registerContext("/export_symbols", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, exportSymbols(params));
        });
        registerContext("/export_function_map", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, exportFunctionMap(params));
        });
        registerContext("/export_c_header", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, exportCHeader(params));
        });
        registerContext("/export_analysis_report", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, exportAnalysisReport(params));
        });

        // ---------- Patch helpers ----------
        registerContext("/assemble_instruction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, assembleInstruction(params, false));
        });
        registerContext("/patch_instruction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, assembleInstruction(params, true));
        });
        registerContext("/nop_range", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, nopRange(params));
        });
        registerContext("/patch_call_target", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, patchFlowTarget(params, true));
        });
        registerContext("/patch_branch_target", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, patchFlowTarget(params, false));
        });
        registerContext("/create_patch_record", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createPatchRecord(params));
        });
        registerContext("/list_patches", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, listPatches(qparams));
        });
        registerContext("/revert_patch", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, revertPatch(params));
        });

        // ---------- Phase 13: project lifecycle ----------
        registerContext("/project_info", exchange -> sendResponse(exchange, projectInfo()));
        registerContext("/open_project", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, openProject(params));
        });
        registerContext("/close_project", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, closeProject(params));
        });
        registerContext("/create_project", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createProject(params));
        });
        registerContext("/save_project", exchange -> sendResponse(exchange, saveProject()));

        // ---------- Phase 13: project file enumeration ----------
        registerContext("/list_project_files", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, listProjectFiles(qparams));
        });
        registerContext("/project_file_exists", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, projectFileExists(qparams));
        });
        registerContext("/delete_project_file", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, deleteProjectFile(params));
        });

        // ---------- Phase 13: loader / language enumeration ----------
        registerContext("/list_loaders", exchange -> sendResponse(exchange, listLoaders()));
        registerContext("/list_languages", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, listLanguages(qparams));
        });
        registerContext("/list_compiler_specs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, listCompilerSpecs(qparams));
        });

        // ---------- Phase 13: async analysis ----------
        registerContext("/start_analysis", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, startAnalysis(params));
        });
        registerContext("/analysis_progress", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, analysisProgress(qparams));
        });
        registerContext("/cancel_analysis", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, cancelAnalysis(params));
        });

        // ---------- Phase 13: navigation / readiness ----------
        registerContext("/ready", exchange -> sendResponse(exchange, ready()));
        registerContext("/agent_hints", exchange -> sendResponse(exchange, agentHints()));
        registerContext("/goto", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, gotoAddress(params));
        });
        registerContext("/select_range", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, selectRange(params));
        });

        // ---------- Phase 13: GBA bring-up helpers ----------
        registerContext("/ensure_gba_memory_map", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, ensureGbaMemoryMap(params));
        });
        registerContext("/bring_up", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, bringUp(params));
        });

        // ---------- Discovery / convenience aliases ----------
        registerContext("/endpoints", exchange -> sendResponse(exchange, listEndpoints()));
        registerContext("/list_endpoints", exchange -> sendResponse(exchange, listEndpoints()));
        registerContext("/help", exchange -> sendResponse(exchange, listEndpoints()));
        registerContext("/list_methods", exchange -> sendResponse(exchange, listEndpoints()));
        registerContext("/count_functions", exchange -> sendResponse(exchange, countFunctions()));
        registerContext("/get_program_info", exchange -> sendResponse(exchange, programInfo()));
        registerContext("/list_memory_blocks", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listMemoryBlocks(offset, limit));
        });
        registerContext("/seed_functions_in_range", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, seedFunctionsInRange(params));
        });
        registerContext("/string_table_at", exchange -> {
            Map<String, String> params = parseAllParams(exchange);
            sendResponse(exchange, stringTableAt(params));
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }    

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return;

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n", 
                func.getName(), 
                func.getEntryPoint()));
        }

        return result.toString();
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    private Function getFunctionByNameExact(Program program, String name) {
        if (name == null || name.isEmpty()) return null;
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                return func;
            }
        }
        return null;
    }

    private Function getFunctionByAddressOrName(Program program, String addressStr, String name) {
        if (addressStr != null && !addressStr.isEmpty()) {
            Address addr = parseAddress(program, addressStr);
            return getFunctionForAddress(program, addr);
        }
        return getFunctionByNameExact(program, name);
    }

    private Address parseAddress(Program program, String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) {
            throw new IllegalArgumentException("address is required");
        }
        Address addr = program.getAddressFactory().getAddress(addressStr);
        if (addr == null) {
            throw new IllegalArgumentException("invalid address: " + addressStr);
        }
        return addr;
    }

    private String getAddressInfo(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            Address addr = parseAddress(program, addressStr);
            Listing listing = program.getListing();
            Memory memory = program.getMemory();
            MemoryBlock block = memory.getBlock(addr);
            CodeUnit cu = listing.getCodeUnitContaining(addr);
            Function func = getFunctionForAddress(program, addr);
            Symbol primary = program.getSymbolTable().getPrimarySymbol(addr);

            Map<String, Object> data = new LinkedHashMap<>();
            data.put("address", addr.toString());
            data.put("address_space", addr.getAddressSpace().getName());
            data.put("offset", Long.toUnsignedString(addr.getUnsignedOffset()));
            data.put("valid_memory", block != null);
            data.put("external", addr.isExternalAddress());
            data.put("memory_block", memoryBlockToMap(block));
            data.put("containing_function", functionSummaryToMap(func));
            data.put("primary_symbol", symbolToMap(primary));
            data.put("symbols", symbolsAtAddressToList(program, addr));
            data.put("code_unit", codeUnitSummaryToMap(program, cu, addr));
            data.put("bytes", readMemoryBytes(program, addr, cu != null ? Math.max(1, Math.min(cu.getLength(), 64)) : 16));
            data.put("comments", commentsToMap(listing, addr));
            data.put("xrefs_to", referencesToList(program, program.getReferenceManager().getReferencesTo(addr), 200));
            data.put("xrefs_from", referencesFromArrayToList(program, program.getReferenceManager().getReferencesFrom(addr), 200));
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("get_address_info error: " + e.getMessage());
        }
    }

    private String getInstructionAt(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            Address addr = parseAddress(program, addressStr);
            Instruction instr = program.getListing().getInstructionAt(addr);
            if (instr == null) {
                instr = program.getListing().getInstructionContaining(addr);
            }
            if (instr == null) {
                return jsonError("No instruction at or containing " + addr);
            }
            return jsonOk(instructionToMap(program, instr, true));
        } catch (Exception e) {
            return jsonError("get_instruction_at error: " + e.getMessage());
        }
    }

    private String getInstructions(String startStr, String endStr, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            Address start = parseAddress(program, startStr);
            Address end = (endStr != null && !endStr.isEmpty()) ? parseAddress(program, endStr) : null;
            int max = Math.max(1, Math.min(limit, 1000));

            List<Object> items = new ArrayList<>();
            InstructionIterator it = program.getListing().getInstructions(start, true);
            while (it.hasNext() && items.size() < max) {
                Instruction instr = it.next();
                if (end != null && instr.getAddress().compareTo(end) > 0) {
                    break;
                }
                items.add(instructionToMap(program, instr, false));
            }

            Map<String, Object> data = new LinkedHashMap<>();
            data.put("start", start.toString());
            data.put("end", end != null ? end.toString() : null);
            data.put("limit", max);
            data.put("count", items.size());
            data.put("items", items);
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("get_instructions error: " + e.getMessage());
        }
    }

    private String getDataAt(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            Address addr = parseAddress(program, addressStr);
            Data data = program.getListing().getDefinedDataAt(addr);
            if (data == null) {
                data = program.getListing().getDefinedDataContaining(addr);
            }
            if (data == null) {
                return jsonError("No defined data at or containing " + addr);
            }
            return jsonOk(dataToMap(program, data, addr));
        } catch (Exception e) {
            return jsonError("get_data_at error: " + e.getMessage());
        }
    }

    private String getFunctionDetails(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            Function func = getFunctionByAddressOrName(program, addressStr, name);
            if (func == null) {
                return jsonError("Function not found");
            }

            Map<String, Object> data = new LinkedHashMap<>();
            data.put("name", func.getName());
            data.put("entry", func.getEntryPoint().toString());
            data.put("namespace", namespaceName(func.getParentNamespace()));
            data.put("signature", func.getSignature().toString());
            data.put("prototype", func.getPrototypeString(false, true));
            data.put("return_type", dataTypeName(func.getReturnType()));
            data.put("calling_convention", func.getCallingConventionName());
            data.put("signature_source", sourceName(func.getSignatureSource()));
            data.put("body_ranges", functionBodyRangesToList(func));
            data.put("parameters", variablesToList(func.getParameters(), "parameter"));
            data.put("locals", variablesToList(func.getLocalVariables(), "local"));

            Map<String, Object> flags = new LinkedHashMap<>();
            flags.put("thunk", func.isThunk());
            flags.put("external", func.isExternal());
            flags.put("no_return", func.hasNoReturn());
            flags.put("inline", func.isInline());
            flags.put("varargs", func.hasVarArgs());
            flags.put("custom_variable_storage", func.hasCustomVariableStorage());
            data.put("flags", flags);

            data.put("comment", func.getComment());
            data.put("repeatable_comment", func.getRepeatableComment());
            data.put("entry_comments", commentsToMap(program.getListing(), func.getEntryPoint()));
            data.put("callers", functionsToList(func.getCallingFunctions(new ConsoleTaskMonitor())));
            data.put("callees", functionsToList(func.getCalledFunctions(new ConsoleTaskMonitor())));
            data.putAll(functionReferenceDetails(program, func));
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("get_function_details error: " + e.getMessage());
        }
    }

    private String listFunctionVariables(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            Function func = getFunctionByAddressOrName(program, addressStr, name);
            if (func == null) {
                return jsonError("Function not found");
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted() || results.getHighFunction() == null) {
                return jsonError("Decompilation failed");
            }

            List<Object> variables = new ArrayList<>();
            LocalSymbolMap localSymbolMap = results.getHighFunction().getLocalSymbolMap();
            Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
            while (symbols.hasNext()) {
                variables.add(highSymbolToMap(symbols.next()));
            }

            Map<String, Object> data = new LinkedHashMap<>();
            data.put("function", functionSummaryToMap(func));
            data.put("count", variables.size());
            data.put("variables", variables);
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("list_function_variables error: " + e.getMessage());
        }
    }

    private String listSymbols(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            String query = params.get("query");
            String type = lower(params.get("type"));
            String source = lower(params.get("source"));
            String blockName = params.get("block");
            Address start = optionalAddress(program, params.get("start"));
            Address end = optionalAddress(program, params.get("end"));
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = Math.max(1, Math.min(parseIntOrDefault(params.get("limit"), 100), 1000));

            List<Object> matches = new ArrayList<>();
            SymbolIterator it = program.getSymbolTable().getAllSymbols(true);
            while (it.hasNext()) {
                Symbol symbol = it.next();
                Address addr = symbol.getAddress();
                if (query != null && !query.isEmpty() &&
                    !symbol.getName(true).toLowerCase().contains(query.toLowerCase())) {
                    continue;
                }
                if (type != null && !type.isEmpty() &&
                    !symbol.getSymbolType().toString().equalsIgnoreCase(type)) {
                    continue;
                }
                if (source != null && !source.isEmpty() &&
                    !sourceName(symbol.getSource()).toLowerCase().contains(source)) {
                    continue;
                }
                if (start != null && addr.compareTo(start) < 0) continue;
                if (end != null && addr.compareTo(end) > 0) continue;
                if (blockName != null && !blockName.isEmpty()) {
                    MemoryBlock block = program.getMemory().getBlock(addr);
                    if (block == null || !block.getName().equals(blockName)) continue;
                }
                matches.add(symbolToDetailedMap(program, symbol));
            }
            return jsonOk(paginatedData(offset, limit, matches));
        } catch (Exception e) {
            return jsonError("list_symbols error: " + e.getMessage());
        }
    }

    private String getSymbol(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            Map<String, Object> data = new LinkedHashMap<>();
            List<Object> symbols = new ArrayList<>();
            if (addressStr != null && !addressStr.isEmpty()) {
                Address addr = parseAddress(program, addressStr);
                for (Symbol symbol : program.getSymbolTable().getSymbols(addr)) {
                    if (name == null || name.isEmpty() || symbol.getName().equals(name) || symbol.getName(true).equals(name)) {
                        symbols.add(symbolToDetailedMap(program, symbol));
                    }
                }
                data.put("address", addr.toString());
                data.put("primary", symbolToDetailedMap(program, program.getSymbolTable().getPrimarySymbol(addr)));
            } else if (name != null && !name.isEmpty()) {
                SymbolIterator it = program.getSymbolTable().getSymbols(name);
                while (it.hasNext()) {
                    symbols.add(symbolToDetailedMap(program, it.next()));
                }
            } else {
                return jsonError("address or name is required");
            }
            data.put("symbols", symbols);
            data.put("count", symbols.size());
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("get_symbol error: " + e.getMessage());
        }
    }

    private String listComments(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            AddressSet set = addressSetFromParams(program, params);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = Math.max(1, Math.min(parseIntOrDefault(params.get("limit"), 100), 1000));
            List<Object> items = new ArrayList<>();
            AddressIterator it = program.getListing().getCommentAddressIterator(set, true);
            while (it.hasNext()) {
                Address addr = it.next();
                Map<String, Object> comments = commentsToMap(program.getListing(), addr);
                for (Object value : comments.values()) {
                    if (value != null) {
                        Map<String, Object> item = new LinkedHashMap<>();
                        item.put("address", addr.toString());
                        item.put("containing_function", functionSummaryToMap(getFunctionForAddress(program, addr)));
                        item.put("comments", comments);
                        items.add(item);
                        break;
                    }
                }
            }
            return jsonOk(paginatedData(offset, limit, items));
        } catch (Exception e) {
            return jsonError("list_comments error: " + e.getMessage());
        }
    }

    private String listBookmarks(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            String type = params.get("type");
            String category = params.get("category");
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = Math.max(1, Math.min(parseIntOrDefault(params.get("limit"), 100), 1000));
            List<Object> items = new ArrayList<>();
            Iterator<Bookmark> it = (type != null && !type.isEmpty())
                ? program.getBookmarkManager().getBookmarksIterator(type)
                : program.getBookmarkManager().getBookmarksIterator();
            while (it.hasNext()) {
                Bookmark bookmark = it.next();
                if (category != null && !category.isEmpty() && !bookmark.getCategory().equals(category)) {
                    continue;
                }
                items.add(bookmarkToMap(program, bookmark));
            }
            return jsonOk(paginatedData(offset, limit, items));
        } catch (Exception e) {
            return jsonError("list_bookmarks error: " + e.getMessage());
        }
    }

    private String getReferences(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            String direction = lower(params.getOrDefault("direction", "both"));
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = Math.max(1, Math.min(parseIntOrDefault(params.get("limit"), 100), 1000));
            List<Object> refs = new ArrayList<>();

            Function func = getFunctionByAddressOrName(program, params.get("function_address"), params.get("function_name"));
            if (func != null) {
                CodeUnitIterator cuIt = program.getListing().getCodeUnits(func.getBody(), true);
                while (cuIt.hasNext()) {
                    CodeUnit cu = cuIt.next();
                    if (!direction.equals("to")) {
                        for (Reference ref : cu.getReferencesFrom()) {
                            refs.add(referenceToMap(program, ref));
                        }
                    }
                }
                if (!direction.equals("from")) {
                    ReferenceIterator toIt = program.getReferenceManager().getReferencesTo(func.getEntryPoint());
                    while (toIt.hasNext()) refs.add(referenceToMap(program, toIt.next()));
                }
            } else {
                Address addr = parseAddress(program, params.get("address"));
                if (!direction.equals("from")) {
                    ReferenceIterator toIt = program.getReferenceManager().getReferencesTo(addr);
                    while (toIt.hasNext()) refs.add(referenceToMap(program, toIt.next()));
                }
                if (!direction.equals("to")) {
                    for (Reference ref : program.getReferenceManager().getReferencesFrom(addr)) {
                        refs.add(referenceToMap(program, ref));
                    }
                }
            }
            return jsonOk(paginatedData(offset, limit, refs));
        } catch (Exception e) {
            return jsonError("get_references error: " + e.getMessage());
        }
    }

    private String setComment(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("set_comment");
                try {
                    Address addr = parseAddress(program, params.get("address"));
                    int commentType = parseCommentType(params.get("type"));
                    String mode = lower(params.getOrDefault("mode", "replace"));
                    String text = params.getOrDefault("text", params.getOrDefault("comment", ""));
                    Listing listing = program.getListing();
                    String current = listing.getComment(commentType, addr);
                    String next;
                    if (mode.equals("clear")) next = null;
                    else if (mode.equals("append")) next = (current == null || current.isEmpty()) ? text : current + "\n" + text;
                    else if (mode.equals("prepend")) next = (current == null || current.isEmpty()) ? text : text + "\n" + current;
                    else next = text;
                    listing.setComment(addr, commentType, next);
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "set_comment", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("set_comment thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("comment updated") : jsonError(err.toString());
    }

    private String setLabel(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        final Map<String, Object> data = new LinkedHashMap<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("set_label");
                try {
                    Address addr = parseAddress(program, params.get("address"));
                    String name = required(params.get("name"), "name");
                    Namespace namespace = resolveNamespace(program, params.get("namespace"), false);
                    SourceType source = parseSourceType(params.get("source"));
                    Symbol symbol = program.getSymbolTable().createLabel(addr, name, namespace, source);
                    if (parseBooleanFlag(params.getOrDefault("primary", "false"))) {
                        symbol.setPrimary();
                    }
                    data.put("symbol", symbolToDetailedMap(program, symbol));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "set_label", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("set_label thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk(data) : jsonError(err.toString());
    }

    private String deleteLabel(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("delete_label");
                try {
                    Address addr = parseAddress(program, params.get("address"));
                    String name = required(params.get("name"), "name");
                    Namespace namespace = resolveNamespace(program, params.get("namespace"), false);
                    Symbol symbol = program.getSymbolTable().getSymbol(name, addr, namespace);
                    if (symbol == null) throw new IllegalArgumentException("label not found");
                    ok.set(symbol.delete());
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "delete_label", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("delete_label thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("label deleted") : jsonError(err.toString());
    }

    private String setPrimarySymbol(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("set_primary_symbol");
                try {
                    Address addr = parseAddress(program, params.get("address"));
                    String name = required(params.get("name"), "name");
                    for (Symbol symbol : program.getSymbolTable().getSymbols(addr)) {
                        if (symbol.getName().equals(name) || symbol.getName(true).equals(name)) {
                            ok.set(symbol.setPrimary());
                            return;
                        }
                    }
                    throw new IllegalArgumentException("symbol not found at address");
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "set_primary_symbol", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("set_primary_symbol thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("primary symbol updated") : jsonError(err.toString());
    }

    private String createNamespace(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        final Map<String, Object> data = new LinkedHashMap<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("create_namespace");
                try {
                    Namespace parent = resolveNamespace(program, params.get("parent"), false);
                    Namespace ns = program.getSymbolTable().getOrCreateNameSpace(
                        parent, required(params.get("name"), "name"), parseSourceType(params.get("source")));
                    data.put("namespace", namespaceToMap(ns));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "create_namespace", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("create_namespace thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk(data) : jsonError(err.toString());
    }

    private String renameNamespace(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("rename_namespace");
                try {
                    Namespace ns = resolveNamespace(program, required(params.get("old_name"), "old_name"), true);
                    ns.getSymbol().setName(required(params.get("new_name"), "new_name"), parseSourceType(params.get("source")));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "rename_namespace", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("rename_namespace thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("namespace renamed") : jsonError(err.toString());
    }

    private String createReference(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        final Map<String, Object> data = new LinkedHashMap<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("create_reference");
                try {
                    Address from = parseAddress(program, params.get("from_address"));
                    Address to = parseAddress(program, params.get("to_address"));
                    int operand = parseIntOrDefault(params.get("operand_index"), Reference.MNEMONIC);
                    Reference ref = program.getReferenceManager().addMemoryReference(
                        from, to, parseRefType(params.get("ref_type")), parseSourceType(params.get("source")), operand);
                    data.put("reference", referenceToMap(program, ref));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "create_reference", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("create_reference thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk(data) : jsonError(err.toString());
    }

    private String createStackReference(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        final Map<String, Object> data = new LinkedHashMap<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("create_stack_reference");
                try {
                    Address from = parseAddress(program, params.get("from_address"));
                    int operand = parseIntOrDefault(params.get("operand_index"), Reference.MNEMONIC);
                    int stackOffset = parseIntOrDefault(params.get("stack_offset"), 0);
                    Reference ref = program.getReferenceManager().addStackReference(
                        from, operand, stackOffset, parseRefType(params.get("ref_type")), parseSourceType(params.get("source")));
                    data.put("reference", referenceToMap(program, ref));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "create_stack_reference", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("create_stack_reference thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk(data) : jsonError(err.toString());
    }

    private String createExternalReference(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        final Map<String, Object> data = new LinkedHashMap<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("create_external_reference");
                try {
                    Address from = parseAddress(program, params.get("from_address"));
                    Address externalAddress = optionalAddress(program, params.get("external_address"));
                    int operand = parseIntOrDefault(params.get("operand_index"), Reference.MNEMONIC);
                    Reference ref = program.getReferenceManager().addExternalReference(
                        from,
                        required(params.get("library"), "library"),
                        required(params.get("label"), "label"),
                        externalAddress,
                        parseSourceType(params.get("source")),
                        operand,
                        parseRefType(params.getOrDefault("ref_type", "external")));
                    data.put("reference", referenceToMap(program, ref));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "create_external_reference", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("create_external_reference thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk(data) : jsonError(err.toString());
    }

    private String deleteReference(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("delete_reference");
                try {
                    Address from = parseAddress(program, params.get("from_address"));
                    Address to = parseAddress(program, params.get("to_address"));
                    int operand = parseIntOrDefault(params.get("operand_index"), Reference.MNEMONIC);
                    Reference ref = program.getReferenceManager().getReference(from, to, operand);
                    if (ref == null) throw new IllegalArgumentException("reference not found");
                    program.getReferenceManager().delete(ref);
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "delete_reference", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("delete_reference thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("reference deleted") : jsonError(err.toString());
    }

    private String setReferencePrimary(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("set_reference_primary");
                try {
                    Address from = parseAddress(program, params.get("from_address"));
                    Address to = parseAddress(program, params.get("to_address"));
                    int operand = parseIntOrDefault(params.get("operand_index"), Reference.MNEMONIC);
                    Reference ref = program.getReferenceManager().getReference(from, to, operand);
                    if (ref == null) throw new IllegalArgumentException("reference not found");
                    program.getReferenceManager().setPrimary(ref, parseBooleanFlag(params.getOrDefault("primary", "true")));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "set_reference_primary", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("set_reference_primary thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("reference primary flag updated") : jsonError(err.toString());
    }

    private String listDataTypes(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            String query = params.get("query");
            String kind = lower(params.get("kind"));
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = Math.max(1, Math.min(parseIntOrDefault(params.get("limit"), 100), 1000));
            List<Object> items = new ArrayList<>();
            Iterator<DataType> it = program.getDataTypeManager().getAllDataTypes();
            while (it.hasNext()) {
                DataType dt = it.next();
                if (query != null && !query.isEmpty() &&
                    !dt.getPathName().toLowerCase().contains(query.toLowerCase())) {
                    continue;
                }
                if (kind != null && !kind.isEmpty() && !dataTypeKind(dt).equals(kind)) {
                    continue;
                }
                items.add(dataTypeToMap(dt, false));
            }
            return jsonOk(paginatedData(offset, limit, items));
        } catch (Exception e) {
            return jsonError("list_data_types error: " + e.getMessage());
        }
    }

    private String getDataType(String path) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            DataType dt = resolveDataTypePath(program.getDataTypeManager(), required(path, "path"));
            if (dt == null) return jsonError("data type not found");
            return jsonOk(dataTypeToMap(dt, true));
        } catch (Exception e) {
            return jsonError("get_data_type error: " + e.getMessage());
        }
    }

    private String getStructLayout(String path) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            DataType dt = resolveDataTypePath(program.getDataTypeManager(), required(path, "path"));
            if (!(dt instanceof Structure)) return jsonError("not a structure data type");
            return jsonOk(structureToMap((Structure) dt));
        } catch (Exception e) {
            return jsonError("get_struct_layout error: " + e.getMessage());
        }
    }

    private String getEnumValues(String path) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            DataType dt = resolveDataTypePath(program.getDataTypeManager(), required(path, "path"));
            if (!(dt instanceof ghidra.program.model.data.Enum)) return jsonError("not an enum data type");
            ghidra.program.model.data.Enum en = (ghidra.program.model.data.Enum) dt;
            Map<String, Object> data = dataTypeToMap(dt, false);
            List<Object> values = new ArrayList<>();
            for (String name : en.getNames()) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("name", name);
                item.put("value", en.getValue(name));
                item.put("comment", en.getComment(name));
                values.add(item);
            }
            data.put("values", values);
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("get_enum_values error: " + e.getMessage());
        }
    }

    private String getTypedefTarget(String path) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            DataType dt = resolveDataTypePath(program.getDataTypeManager(), required(path, "path"));
            if (!(dt instanceof TypeDef)) return jsonError("not a typedef data type");
            TypeDef td = (TypeDef) dt;
            Map<String, Object> data = dataTypeToMap(dt, false);
            data.put("target", dataTypeToMap(td.getDataType(), false));
            data.put("base_target", dataTypeToMap(td.getBaseDataType(), false));
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("get_typedef_target error: " + e.getMessage());
        }
    }

    private String applyDataTypeAt(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        final Map<String, Object> data = new LinkedHashMap<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("apply_data_type");
                try {
                    Address addr = parseAddress(program, params.get("address"));
                    DataType dt = resolveDataTypePath(program.getDataTypeManager(), required(params.get("type_path"), "type_path"));
                    if (dt == null) throw new IllegalArgumentException("data type not found");
                    int length = parseIntOrDefault(params.get("length"), dt.getLength());
                    String clearMode = lower(params.getOrDefault("clear_mode", "conflicts"));
                    if (!clearMode.equals("none")) {
                        int clearLength = Math.max(1, length > 0 ? length : dt.getLength());
                        program.getListing().clearCodeUnits(addr, addr.add(clearLength - 1), false);
                    }
                    Data created = length > 0 ? program.getListing().createData(addr, dt, length) : program.getListing().createData(addr, dt);
                    data.put("data", dataToMap(program, created, addr));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "apply_data_type", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("apply_data_type thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk(data) : jsonError(err.toString());
    }

    private String createStruct(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "create_struct", () -> {
            CategoryPath category = categoryPath(params.get("category"));
            StructureDataType structure = new StructureDataType(
                category,
                required(params.get("name"), "name"),
                Math.max(0, parseIntOrDefault(params.get("length"), 0)),
                program.getDataTypeManager());
            DataType added = program.getDataTypeManager().addDataType(structure, DataTypeConflictHandler.DEFAULT_HANDLER);
            return dataTypeToMap(added, true);
        });
    }

    private String deleteDataType(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "delete_data_type", () -> {
            DataType dt = requireDataType(program, params.get("path"));
            boolean removed = program.getDataTypeManager().remove(dt);
            if (!removed) throw new IllegalArgumentException("data type was not removed");
            return "data type deleted";
        });
    }

    private String renameDataType(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "rename_data_type", () -> {
            DataType dt = requireDataType(program, params.get("path"));
            String newName = params.get("new_name");
            String newCategory = params.get("category");
            if (newCategory != null && !newCategory.isEmpty()) {
                dt.setNameAndCategory(categoryPath(newCategory), required(newName, "new_name"));
            } else {
                dt.setName(required(newName, "new_name"));
            }
            return dataTypeToMap(dt, true);
        });
    }

    private String addStructField(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "add_struct_field", () -> {
            Structure structure = requireStructure(program, params.get("path"));
            DataType fieldType = requireDataType(program, params.get("type_path"));
            int length = parseIntOrDefault(params.get("length"), fieldType.getLength());
            DataTypeComponent component = structure.add(
                fieldType,
                length,
                params.get("field_name"),
                params.get("comment"));
            return dataTypeComponentToMap(component);
        });
    }

    private String renameStructField(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "rename_struct_field", () -> {
            DataTypeComponent component = structComponentFromParams(requireStructure(program, params.get("path")), params);
            component.setFieldName(required(params.get("new_name"), "new_name"));
            return dataTypeComponentToMap(component);
        });
    }

    private String setStructFieldType(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "set_struct_field_type", () -> {
            Structure structure = requireStructure(program, params.get("path"));
            DataTypeComponent old = structComponentFromParams(structure, params);
            DataType fieldType = requireDataType(program, params.get("type_path"));
            int length = parseIntOrDefault(params.get("length"), fieldType.getLength());
            DataTypeComponent component = structure.replace(
                old.getOrdinal(),
                fieldType,
                length,
                params.getOrDefault("field_name", old.getFieldName()),
                params.getOrDefault("comment", old.getComment()));
            return dataTypeComponentToMap(component);
        });
    }

    private String deleteStructField(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "delete_struct_field", () -> {
            Structure structure = requireStructure(program, params.get("path"));
            DataTypeComponent component = structComponentFromParams(structure, params);
            structure.delete(component.getOrdinal());
            return structureToMap(structure);
        });
    }

    private String createEnum(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "create_enum", () -> {
            EnumDataType enumType = new EnumDataType(
                categoryPath(params.get("category")),
                required(params.get("name"), "name"),
                Math.max(1, parseIntOrDefault(params.get("length"), 4)),
                program.getDataTypeManager());
            DataType added = program.getDataTypeManager().addDataType(enumType, DataTypeConflictHandler.DEFAULT_HANDLER);
            return dataTypeToMap(added, true);
        });
    }

    private String setEnumValue(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "set_enum_value", () -> {
            DataType dt = requireDataType(program, params.get("path"));
            if (!(dt instanceof ghidra.program.model.data.Enum)) throw new IllegalArgumentException("not an enum");
            ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dt;
            String name = required(params.get("name"), "name");
            long value = parseLongOrDefault(required(params.get("value"), "value"), 0);
            if (enumType.contains(name)) enumType.remove(name);
            enumType.add(name, value, params.get("comment"));
            return dataTypeToMap(dt, true);
        });
    }

    private String createTypedef(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "create_typedef", () -> {
            DataType target = requireDataType(program, params.get("target_path"));
            TypedefDataType typedef = new TypedefDataType(
                categoryPath(params.get("category")),
                required(params.get("name"), "name"),
                target,
                program.getDataTypeManager());
            DataType added = program.getDataTypeManager().addDataType(typedef, DataTypeConflictHandler.DEFAULT_HANDLER);
            return dataTypeToMap(added, true);
        });
    }

    private String createPointerType(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "create_pointer_type", () -> {
            DataType target = requireDataType(program, params.get("target_path"));
            int size = parseIntOrDefault(params.get("size"), -1);
            DataType pointer = size > 0 ? program.getDataTypeManager().getPointer(target, size) : program.getDataTypeManager().getPointer(target);
            String name = params.get("name");
            if (name != null && !name.isEmpty()) {
                pointer = program.getDataTypeManager().addDataType(
                    new TypedefDataType(categoryPath(params.get("category")), name, pointer, program.getDataTypeManager()),
                    DataTypeConflictHandler.DEFAULT_HANDLER);
            }
            return dataTypeToMap(pointer, true);
        });
    }

    private String createArrayType(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "create_array_type", () -> {
            DataType element = requireDataType(program, params.get("element_type_path"));
            int count = Math.max(1, parseIntOrDefault(params.get("count"), 1));
            ArrayDataType array = new ArrayDataType(element, count, element.getLength());
            String name = params.get("name");
            DataType result = array;
            if (name != null && !name.isEmpty()) {
                result = program.getDataTypeManager().addDataType(
                    new TypedefDataType(categoryPath(params.get("category")), name, array, program.getDataTypeManager()),
                    DataTypeConflictHandler.DEFAULT_HANDLER);
            }
            return dataTypeToMap(result, true);
        });
    }

    private String createFunctionDefinitionType(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "create_function_definition_type", () -> {
            ghidra.app.services.DataTypeManagerService dtms =
                tool.getService(ghidra.app.services.DataTypeManagerService.class);
            ghidra.app.util.parser.FunctionSignatureParser parser =
                new ghidra.app.util.parser.FunctionSignatureParser(program.getDataTypeManager(), dtms);
            ghidra.program.model.data.FunctionDefinitionDataType sig =
                parser.parse(null, required(params.get("prototype"), "prototype"));
            DataType added = program.getDataTypeManager().addDataType(sig, DataTypeConflictHandler.DEFAULT_HANDLER);
            return dataTypeToMap(added, true);
        });
    }

    private String setFunctionName(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("set_function_name");
                try {
                    Function func = functionFromParams(program, params);
                    Namespace namespace = resolveNamespace(program, params.get("namespace"), false);
                    func.getSymbol().setNameAndNamespace(
                        required(params.get("name"), "name"),
                        namespace,
                        parseSourceType(params.get("source")));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "set_function_name", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("set_function_name thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("function name updated") : jsonError(err.toString());
    }

    private String setFunctionReturnType(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("set_function_return_type");
                try {
                    Function func = functionFromParams(program, params);
                    DataType dt = resolveDataTypePath(program.getDataTypeManager(), required(params.get("type_path"), "type_path"));
                    if (dt == null) throw new IllegalArgumentException("data type not found");
                    func.setReturnType(dt, parseSourceType(params.get("source")));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "set_function_return_type", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("set_function_return_type thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("function return type updated") : jsonError(err.toString());
    }

    private String setFunctionCallingConvention(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("set_function_calling_convention");
                try {
                    functionFromParams(program, params).setCallingConvention(required(params.get("calling_convention"), "calling_convention"));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "set_function_calling_convention", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("set_function_calling_convention thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("function calling convention updated") : jsonError(err.toString());
    }

    private String setFunctionFlag(Map<String, String> params, String flag) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("set_function_" + flag);
                try {
                    Function func = functionFromParams(program, params);
                    boolean enabled = parseBooleanFlag(params.getOrDefault("enabled", params.getOrDefault("value", "true")));
                    if (flag.equals("no_return")) func.setNoReturn(enabled);
                    else if (flag.equals("inline")) func.setInline(enabled);
                    else if (flag.equals("varargs")) func.setVarArgs(enabled);
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "set_function_" + flag, e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("set_function_" + flag + " thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("function flag updated") : jsonError(err.toString());
    }

    private String setFunctionThunk(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("set_function_thunk");
                try {
                    Function func = functionFromParams(program, params);
                    Function target = getFunctionForAddress(program, parseAddress(program, params.get("target_address")));
                    if (target == null) throw new IllegalArgumentException("target function not found");
                    func.setThunkedFunction(target);
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "set_function_thunk", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("set_function_thunk thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("function thunk target updated") : jsonError(err.toString());
    }

    private String setFunctionComment(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("set_function_comment");
                try {
                    Function func = functionFromParams(program, params);
                    String mode = lower(params.getOrDefault("mode", "replace"));
                    String text = params.getOrDefault("text", params.getOrDefault("comment", ""));
                    String current = parseBooleanFlag(params.getOrDefault("repeatable", "false"))
                        ? func.getRepeatableComment()
                        : func.getComment();
                    String next = mode.equals("clear") ? null
                        : mode.equals("append") ? ((current == null || current.isEmpty()) ? text : current + "\n" + text)
                        : mode.equals("prepend") ? ((current == null || current.isEmpty()) ? text : text + "\n" + current)
                        : text;
                    if (parseBooleanFlag(params.getOrDefault("repeatable", "false"))) func.setRepeatableComment(next);
                    else func.setComment(next);
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "set_function_comment", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("set_function_comment thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("function comment updated") : jsonError(err.toString());
    }

    private String listParameters(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            Function func = functionFromParams(program, params);
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("function", functionSummaryToMap(func));
            data.put("parameters", variablesToList(func.getParameters(), "parameter"));
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("list_parameters error: " + e.getMessage());
        }
    }

    private String renameParameter(Map<String, String> params) {
        return updateParameter(params, "rename");
    }

    private String setParameterType(Map<String, String> params) {
        return updateParameter(params, "type");
    }

    private String setParameterStorage(Map<String, String> params) {
        return updateParameter(params, "storage");
    }

    private String updateParameter(Map<String, String> params, String mode) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(mode + "_parameter");
                try {
                    Function func = functionFromParams(program, params);
                    Parameter parameter = parameterFromParams(func, params);
                    SourceType source = parseSourceType(params.get("source"));
                    if (mode.equals("rename")) {
                        parameter.setName(required(params.get("new_name"), "new_name"), source);
                    } else if (mode.equals("type")) {
                        DataType dt = resolveDataTypePath(program.getDataTypeManager(), required(params.get("type_path"), "type_path"));
                        if (dt == null) throw new IllegalArgumentException("data type not found");
                        parameter.setDataType(dt, source);
                    } else {
                        VariableStorage storage = VariableStorage.deserialize(program, required(params.get("storage"), "storage"));
                        parameter.setDataType(parameter.getDataType(), storage, false, source);
                    }
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, mode + "_parameter", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError(mode + "_parameter thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("parameter updated") : jsonError(err.toString());
    }

    private String addParameter(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("add_parameter");
                try {
                    Function func = functionFromParams(program, params);
                    DataType dt = resolveDataTypePath(program.getDataTypeManager(), required(params.get("type_path"), "type_path"));
                    if (dt == null) throw new IllegalArgumentException("data type not found");
                    ParameterImpl parameter = new ParameterImpl(required(params.get("name"), "name"), dt, program, parseSourceType(params.get("source")));
                    int ordinal = parseIntOrDefault(params.get("ordinal"), -1);
                    if (ordinal >= 0) func.insertParameter(ordinal, parameter, parseSourceType(params.get("source")));
                    else func.addParameter(parameter, parseSourceType(params.get("source")));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "add_parameter", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("add_parameter thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("parameter added") : jsonError(err.toString());
    }

    private String removeParameter(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("remove_parameter");
                try {
                    Function func = functionFromParams(program, params);
                    func.removeParameter(parameterFromParams(func, params).getOrdinal());
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "remove_parameter", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("remove_parameter thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("parameter removed") : jsonError(err.toString());
    }

    private String reorderParameters(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("reorder_parameters");
                try {
                    Function func = functionFromParams(program, params);
                    int from = parseIntOrDefault(params.get("from_ordinal"), -1);
                    int to = parseIntOrDefault(params.get("to_ordinal"), -1);
                    if (from < 0 || to < 0) throw new IllegalArgumentException("from_ordinal and to_ordinal are required");
                    func.moveParameter(from, to);
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "reorder_parameters", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("reorder_parameters thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("parameters reordered") : jsonError(err.toString());
    }

    private String renameVariableByStorage(Map<String, String> params) {
        return updateVariableByStorage(params, "rename");
    }

    private String setVariableTypeByStorage(Map<String, String> params) {
        return updateVariableByStorage(params, "type");
    }

    private String updateVariableByStorage(Map<String, String> params, String mode) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(mode + "_variable_by_storage");
                try {
                    Function func = functionFromParams(program, params);
                    Variable variable = variableByStorage(func, required(params.get("storage"), "storage"));
                    SourceType source = parseSourceType(params.get("source"));
                    if (mode.equals("rename")) {
                        variable.setName(required(params.get("new_name"), "new_name"), source);
                    } else {
                        DataType dt = resolveDataTypePath(program.getDataTypeManager(), required(params.get("type_path"), "type_path"));
                        if (dt == null) throw new IllegalArgumentException("data type not found");
                        variable.setDataType(dt, source);
                    }
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, mode + "_variable_by_storage", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError(mode + "_variable_by_storage thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("variable updated") : jsonError(err.toString());
    }

    private String createStackVariable(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("create_stack_variable");
                try {
                    Function func = functionFromParams(program, params);
                    DataType dt = resolveDataTypePath(program.getDataTypeManager(), required(params.get("type_path"), "type_path"));
                    if (dt == null) throw new IllegalArgumentException("data type not found");
                    int offset = parseIntOrDefault(params.get("stack_offset"), 0);
                    func.getStackFrame().createVariable(required(params.get("name"), "name"), offset, dt, parseSourceType(params.get("source")));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "create_stack_variable", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("create_stack_variable thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("stack variable created") : jsonError(err.toString());
    }

    private String deleteStackVariable(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("delete_stack_variable");
                try {
                    functionFromParams(program, params).getStackFrame().clearVariable(parseIntOrDefault(params.get("stack_offset"), 0));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "delete_stack_variable", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("delete_stack_variable thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("stack variable deleted") : jsonError(err.toString());
    }

    private String setStackVariableType(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("set_stack_variable_type");
                try {
                    Function func = functionFromParams(program, params);
                    Variable variable = func.getStackFrame().getVariableContaining(parseIntOrDefault(params.get("stack_offset"), 0));
                    if (variable == null) throw new IllegalArgumentException("stack variable not found");
                    DataType dt = resolveDataTypePath(program.getDataTypeManager(), required(params.get("type_path"), "type_path"));
                    if (dt == null) throw new IllegalArgumentException("data type not found");
                    variable.setDataType(dt, parseSourceType(params.get("source")));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "set_stack_variable_type", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("set_stack_variable_type thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk("stack variable type updated") : jsonError(err.toString());
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted())
                ? result.getDecompiledFunction().getC()
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                
                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }
                
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                
                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }
        
        return paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    private Map<String, Object> memoryBlockToMap(MemoryBlock block) {
        if (block == null) return null;
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("name", block.getName());
        map.put("start", block.getStart().toString());
        map.put("end", block.getEnd().toString());
        map.put("size", block.getSize());
        map.put("read", block.isRead());
        map.put("write", block.isWrite());
        map.put("execute", block.isExecute());
        map.put("initialized", block.isInitialized());
        map.put("volatile", block.isVolatile());
        map.put("overlay", block.isOverlay());
        map.put("type", block.getType().toString());
        return map;
    }

    private Map<String, Object> functionSummaryToMap(Function func) {
        if (func == null) return null;
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("name", func.getName());
        map.put("entry", func.getEntryPoint().toString());
        map.put("namespace", namespaceName(func.getParentNamespace()));
        map.put("signature", func.getSignature().toString());
        return map;
    }

    private List<Object> functionsToList(Collection<Function> functions) {
        List<Object> items = new ArrayList<>();
        for (Function func : functions) {
            items.add(functionSummaryToMap(func));
        }
        return items;
    }

    private Map<String, Object> symbolToMap(Symbol symbol) {
        if (symbol == null) return null;
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("name", symbol.getName());
        map.put("address", symbol.getAddress() != null ? symbol.getAddress().toString() : null);
        map.put("namespace", namespaceName(symbol.getParentNamespace()));
        map.put("type", symbol.getSymbolType().toString());
        map.put("source", sourceName(symbol.getSource()));
        map.put("primary", symbol.isPrimary());
        map.put("external", symbol.isExternal());
        map.put("global", symbol.isGlobal());
        return map;
    }

    private Map<String, Object> symbolToDetailedMap(Program program, Symbol symbol) {
        if (symbol == null) return null;
        Map<String, Object> map = symbolToMap(symbol);
        map.put("full_name", symbol.getName(true));
        map.put("id", symbol.getID());
        map.put("pinned", symbol.isPinned());
        map.put("dynamic", symbol.isDynamic());
        map.put("reference_count", symbol.getReferenceCount());
        map.put("containing_function", functionSummaryToMap(getFunctionForAddress(program, symbol.getAddress())));
        return map;
    }

    private Map<String, Object> namespaceToMap(Namespace namespace) {
        if (namespace == null) return null;
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", namespace.getID());
        map.put("name", namespace.getName());
        map.put("full_name", namespace.getName(true));
        map.put("type", namespace.getType().toString());
        map.put("external", namespace.isExternal());
        map.put("global", namespace.isGlobal());
        map.put("parent", namespace.getParentNamespace() != null ? namespace.getParentNamespace().getName(true) : null);
        return map;
    }

    private List<Object> symbolsAtAddressToList(Program program, Address addr) {
        List<Object> symbols = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getSymbols(addr)) {
            symbols.add(symbolToMap(symbol));
        }
        return symbols;
    }

    private Map<String, Object> codeUnitSummaryToMap(Program program, CodeUnit cu, Address requested) {
        Map<String, Object> map = new LinkedHashMap<>();
        if (cu == null) {
            map.put("kind", program.getMemory().getBlock(requested) != null ? "undefined" : "invalid");
            return map;
        }

        String kind = "defined_data";
        if (cu instanceof Instruction) {
            kind = "instruction";
        } else if (cu instanceof Data && !((Data) cu).isDefined()) {
            kind = "undefined_data";
        }

        map.put("kind", kind);
        map.put("start", cu.getMinAddress().toString());
        map.put("end", cu.getMaxAddress().toString());
        map.put("length", cu.getLength());
        map.put("mnemonic", cu.getMnemonicString());
        map.put("label", cu.getLabel());
        if (cu instanceof Data) {
            Data data = (Data) cu;
            map.put("data_type", dataTypeName(data.getDataType()));
            map.put("value", safeString(data.getDefaultValueRepresentation()));
        }
        return map;
    }

    private Map<String, Object> commentsToMap(Listing listing, Address addr) {
        Map<String, Object> comments = new LinkedHashMap<>();
        comments.put("plate", listing.getComment(CodeUnit.PLATE_COMMENT, addr));
        comments.put("pre", listing.getComment(CodeUnit.PRE_COMMENT, addr));
        comments.put("post", listing.getComment(CodeUnit.POST_COMMENT, addr));
        comments.put("eol", listing.getComment(CodeUnit.EOL_COMMENT, addr));
        comments.put("repeatable", listing.getComment(CodeUnit.REPEATABLE_COMMENT, addr));
        return comments;
    }

    private Map<String, Object> instructionToMap(Program program, Instruction instr, boolean includePcode) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("address", instr.getAddress().toString());
        map.put("mnemonic", instr.getMnemonicString());
        map.put("text", instr.toString());
        map.put("length", instr.getLength());
        map.put("bytes", bytesToHex(safeCodeUnitBytes(instr)));

        List<Object> operands = new ArrayList<>();
        for (int i = 0; i < instr.getNumOperands(); i++) {
            Map<String, Object> operand = new LinkedHashMap<>();
            operand.put("index", i);
            operand.put("text", instr.getDefaultOperandRepresentation(i));
            operand.put("type", instr.getOperandType(i));
            RefType refType = instr.getOperandRefType(i);
            operand.put("ref_type", refType != null ? refType.getName() : null);
            operands.add(operand);
        }
        map.put("operands", operands);
        map.put("fallthrough", instr.getFallThrough() != null ? instr.getFallThrough().toString() : null);
        map.put("default_fallthrough", instr.getDefaultFallThrough() != null ? instr.getDefaultFallThrough().toString() : null);
        map.put("flow_type", instr.getFlowType() != null ? instr.getFlowType().getName() : null);
        map.put("flows", addressesToList(instr.getFlows()));
        map.put("containing_function", functionSummaryToMap(getFunctionForAddress(program, instr.getAddress())));
        map.put("comments", commentsToMap(program.getListing(), instr.getAddress()));

        if (includePcode) {
            List<Object> pcode = new ArrayList<>();
            for (PcodeOp op : instr.getPcode()) {
                pcode.add(op.toString());
            }
            map.put("pcode", pcode);
        }
        return map;
    }

    private Map<String, Object> dataToMap(Program program, Data data, Address requested) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("address", data.getAddress().toString());
        map.put("requested_address", requested.toString());
        map.put("end", data.getMaxAddress().toString());
        map.put("length", data.getLength());
        map.put("data_type", dataTypeName(data.getDataType()));
        map.put("data_type_path", data.getDataType() != null ? data.getDataType().getPathName() : null);
        map.put("base_data_type", dataTypeName(data.getBaseDataType()));
        map.put("value", safeString(data.getDefaultValueRepresentation()));
        map.put("raw_bytes", bytesToHex(safeCodeUnitBytes(data)));
        map.put("label", data.getLabel());
        map.put("path_name", data.getPathName());
        map.put("component_path_name", data.getComponentPathName());
        map.put("field_name", data.getFieldName());
        map.put("component_index", data.getComponentIndex());
        map.put("component_level", data.getComponentLevel());
        map.put("parent", data.getParent() != null ? dataComponentSummaryToMap(data.getParent()) : null);
        map.put("root", data.getRoot() != null && data.getRoot() != data ? dataComponentSummaryToMap(data.getRoot()) : null);
        map.put("comments", commentsToMap(program.getListing(), data.getAddress()));

        List<Object> components = new ArrayList<>();
        int n = Math.min(data.getNumComponents(), 128);
        for (int i = 0; i < n; i++) {
            Data component = data.getComponent(i);
            if (component != null) {
                components.add(dataComponentSummaryToMap(component));
            }
        }
        map.put("component_count", data.getNumComponents());
        map.put("components", components);
        return map;
    }

    private Map<String, Object> dataComponentSummaryToMap(Data data) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("address", data.getAddress().toString());
        map.put("end", data.getMaxAddress().toString());
        map.put("offset", data.getParentOffset());
        map.put("length", data.getLength());
        map.put("data_type", dataTypeName(data.getDataType()));
        map.put("field_name", data.getFieldName());
        map.put("value", safeString(data.getDefaultValueRepresentation()));
        return map;
    }

    private List<Object> functionBodyRangesToList(Function func) {
        List<Object> ranges = new ArrayList<>();
        for (AddressRange range : func.getBody()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("start", range.getMinAddress().toString());
            item.put("end", range.getMaxAddress().toString());
            item.put("length", range.getLength());
            ranges.add(item);
        }
        return ranges;
    }

    private List<Object> variablesToList(Variable[] variables, String kind) {
        List<Object> items = new ArrayList<>();
        for (Variable variable : variables) {
            items.add(variableToMap(variable, kind));
        }
        return items;
    }

    private Map<String, Object> variableToMap(Variable variable, String kind) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("name", variable.getName());
        map.put("kind", kind);
        map.put("data_type", dataTypeName(variable.getDataType()));
        map.put("storage", variable.getVariableStorage() != null ? variable.getVariableStorage().toString() : null);
        map.put("size", variable.getLength());
        map.put("source", sourceName(variable.getSource()));
        map.put("first_use_offset", variable.getFirstUseOffset());
        map.put("comment", variable.getComment());
        if (variable instanceof Parameter) {
            Parameter parameter = (Parameter) variable;
            map.put("ordinal", parameter.getOrdinal());
            map.put("auto_parameter", parameter.isAutoParameter());
            map.put("auto_parameter_type", parameter.getAutoParameterType() != null ? parameter.getAutoParameterType().toString() : null);
        }
        return map;
    }

    private Map<String, Object> highSymbolToMap(HighSymbol symbol) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("name", symbol.getName());
        map.put("data_type", dataTypeName(symbol.getDataType()));
        map.put("storage", symbol.getStorage() != null ? symbol.getStorage().toString() : null);
        map.put("size", symbol.getSize());
        map.put("source", symbol.getSymbol() != null ? sourceName(symbol.getSymbol().getSource()) : null);
        map.put("parameter", symbol.isParameter());
        map.put("global", symbol.isGlobal());
        map.put("category_index", symbol.getCategoryIndex());
        map.put("pc_address", symbol.getPCAddress() != null ? symbol.getPCAddress().toString() : null);

        HighVariable highVariable = symbol.getHighVariable();
        List<Object> varnodes = new ArrayList<>();
        if (highVariable != null) {
            for (Varnode varnode : highVariable.getInstances()) {
                varnodes.add(varnode.toString());
            }
            map.put("representative_varnode", highVariable.getRepresentative() != null ? highVariable.getRepresentative().toString() : null);
        } else {
            map.put("representative_varnode", null);
        }
        map.put("varnodes", varnodes);
        return map;
    }

    private Map<String, Object> bookmarkToMap(Program program, Bookmark bookmark) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", bookmark.getId());
        map.put("address", bookmark.getAddress().toString());
        map.put("type", bookmark.getTypeString());
        map.put("category", bookmark.getCategory());
        map.put("comment", bookmark.getComment());
        map.put("containing_function", functionSummaryToMap(getFunctionForAddress(program, bookmark.getAddress())));
        return map;
    }

    private Map<String, Object> dataTypeToMap(DataType dt, boolean includeDetails) {
        if (dt == null) return null;
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("name", dt.getName());
        map.put("display_name", dt.getDisplayName());
        map.put("path", dt.getPathName());
        map.put("category", dt.getCategoryPath() != null ? dt.getCategoryPath().getPath() : null);
        map.put("kind", dataTypeKind(dt));
        map.put("length", dt.getLength());
        map.put("aligned_length", dt.getAlignedLength());
        map.put("description", dt.getDescription());
        map.put("source_archive", dt.getSourceArchive() != null ? dt.getSourceArchive().getName() : null);
        if (includeDetails) {
            if (dt instanceof Structure) {
                map.put("layout", structureToMap((Structure) dt));
            } else if (dt instanceof ghidra.program.model.data.Enum) {
                ghidra.program.model.data.Enum en = (ghidra.program.model.data.Enum) dt;
                List<Object> values = new ArrayList<>();
                for (String name : en.getNames()) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("name", name);
                    item.put("value", en.getValue(name));
                    item.put("comment", en.getComment(name));
                    values.add(item);
                }
                map.put("values", values);
            } else if (dt instanceof TypeDef) {
                TypeDef td = (TypeDef) dt;
                map.put("target", dataTypeToMap(td.getDataType(), false));
            }
        }
        return map;
    }

    private Map<String, Object> structureToMap(Structure structure) {
        Map<String, Object> map = dataTypeToMap(structure, false);
        map.put("component_count", structure.getNumComponents());
        map.put("defined_component_count", structure.getNumDefinedComponents());
        map.put("packing", structure.getPackingType().toString());
        map.put("alignment", structure.getAlignment());
        List<Object> fields = new ArrayList<>();
        for (DataTypeComponent component : structure.getDefinedComponents()) {
            fields.add(dataTypeComponentToMap(component));
        }
        map.put("fields", fields);
        return map;
    }

    private Map<String, Object> dataTypeComponentToMap(DataTypeComponent component) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("ordinal", component.getOrdinal());
        map.put("offset", component.getOffset());
        map.put("end_offset", component.getEndOffset());
        map.put("length", component.getLength());
        map.put("field_name", component.getFieldName());
        map.put("data_type", dataTypeToMap(component.getDataType(), false));
        map.put("comment", component.getComment());
        map.put("bit_field", component.isBitFieldComponent());
        return map;
    }

    private String dataTypeKind(DataType dt) {
        if (dt instanceof Structure) return "structure";
        if (dt instanceof ghidra.program.model.data.Enum) return "enum";
        if (dt instanceof TypeDef) return "typedef";
        if (dt instanceof Composite) return "composite";
        if (dt instanceof PointerDataType) return "pointer";
        if (dt instanceof ArrayDataType) return "array";
        return "data";
    }

    private Map<String, Object> functionReferenceDetails(Program program, Function func) {
        Map<String, Object> details = new LinkedHashMap<>();
        List<Object> outboundRefs = new ArrayList<>();
        Map<String, Object> referencedData = new LinkedHashMap<>();
        Map<String, Object> referencedStrings = new LinkedHashMap<>();

        CodeUnitIterator it = program.getListing().getCodeUnits(func.getBody(), true);
        while (it.hasNext() && outboundRefs.size() < 1000) {
            CodeUnit cu = it.next();
            for (Reference ref : cu.getReferencesFrom()) {
                outboundRefs.add(referenceToMap(program, ref));
                Address to = ref.getToAddress();
                Data data = program.getListing().getDefinedDataContaining(to);
                if (data != null) {
                    referencedData.putIfAbsent(data.getAddress().toString(), dataComponentSummaryToMap(data));
                    if (isStringData(data)) {
                        Map<String, Object> str = dataComponentSummaryToMap(data);
                        Object value = data.getValue();
                        str.put("string", value != null ? value.toString() : "");
                        referencedStrings.putIfAbsent(data.getAddress().toString(), str);
                    }
                }
            }
        }

        details.put("outbound_references", outboundRefs);
        details.put("referenced_data", new ArrayList<>(referencedData.values()));
        details.put("referenced_strings", new ArrayList<>(referencedStrings.values()));
        return details;
    }

    private List<Object> referencesToList(Program program, ReferenceIterator iterator, int limit) {
        List<Object> refs = new ArrayList<>();
        while (iterator.hasNext() && refs.size() < limit) {
            refs.add(referenceToMap(program, iterator.next()));
        }
        return refs;
    }

    private List<Object> referencesFromArrayToList(Program program, Reference[] references, int limit) {
        List<Object> refs = new ArrayList<>();
        for (Reference ref : references) {
            if (refs.size() >= limit) break;
            refs.add(referenceToMap(program, ref));
        }
        return refs;
    }

    private Map<String, Object> referenceToMap(Program program, Reference ref) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("from", ref.getFromAddress().toString());
        map.put("to", ref.getToAddress().toString());
        map.put("type", ref.getReferenceType() != null ? ref.getReferenceType().getName() : null);
        map.put("operand_index", ref.getOperandIndex());
        map.put("source", sourceName(ref.getSource()));
        map.put("primary", ref.isPrimary());
        map.put("memory", ref.isMemoryReference());
        map.put("external", ref.isExternalReference());
        map.put("from_function", functionSummaryToMap(getFunctionForAddress(program, ref.getFromAddress())));
        map.put("to_function", functionSummaryToMap(getFunctionForAddress(program, ref.getToAddress())));
        map.put("to_symbol", symbolToMap(program.getSymbolTable().getPrimarySymbol(ref.getToAddress())));
        return map;
    }

    private List<Object> addressesToList(Address[] addresses) {
        List<Object> items = new ArrayList<>();
        for (Address address : addresses) {
            items.add(address.toString());
        }
        return items;
    }

    private byte[] safeCodeUnitBytes(CodeUnit cu) {
        try {
            return cu.getBytes();
        } catch (MemoryAccessException e) {
            return new byte[0];
        }
    }

    private String readMemoryBytes(Program program, Address addr, int length) {
        if (program.getMemory().getBlock(addr) == null) return "";
        try {
            byte[] buf = new byte[Math.max(1, length)];
            int n = program.getMemory().getBytes(addr, buf);
            return bytesToHex(Arrays.copyOf(buf, Math.max(0, n)));
        } catch (Exception e) {
            return "";
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private String namespaceName(Namespace namespace) {
        if (namespace == null) return null;
        return namespace.getName(true);
    }

    private String sourceName(SourceType sourceType) {
        return sourceType != null ? sourceType.toString() : null;
    }

    private String dataTypeName(DataType dataType) {
        return dataType != null ? dataType.getDisplayName() : null;
    }

    private String safeString(String input) {
        return input != null ? input : "";
    }

    private String jsonOk(Object data) {
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("ok", true);
        envelope.put("data", data);
        envelope.put("error", null);
        return toJson(envelope);
    }

    private String jsonError(String error) {
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("ok", false);
        envelope.put("data", null);
        envelope.put("error", error);
        return toJson(envelope);
    }

    private String toJson(Object value) {
        if (value == null) return "null";
        if (value instanceof String) return "\"" + jsonEscape((String) value) + "\"";
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        if (value instanceof Map<?, ?>) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                if (!first) sb.append(",");
                first = false;
                sb.append(toJson(String.valueOf(entry.getKey())));
                sb.append(":");
                sb.append(toJson(entry.getValue()));
            }
            sb.append("}");
            return sb.toString();
        }
        if (value instanceof Iterable<?>) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (Object item : (Iterable<?>) value) {
                if (!first) sb.append(",");
                first = false;
                sb.append(toJson(item));
            }
            sb.append("]");
            return sb.toString();
        }
        return "\"" + jsonEscape(String.valueOf(value)) + "\"";
    }

    private String jsonEscape(String input) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    private Map<String, Object> paginatedData(int offset, int limit, List<Object> items) {
        int start = Math.max(0, offset);
        int end = Math.min(items.size(), start + Math.max(1, limit));
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("offset", start);
        data.put("limit", limit);
        data.put("count", start >= items.size() ? 0 : end - start);
        data.put("total_known", items.size());
        data.put("items", start >= items.size() ? new ArrayList<>() : new ArrayList<>(items.subList(start, end)));
        return data;
    }

    private String lower(String value) {
        return value != null ? value.toLowerCase() : null;
    }

    private String required(String value, String name) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    private Address optionalAddress(Program program, String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) return null;
        return parseAddress(program, addressStr);
    }

    private AddressSet addressSetFromParams(Program program, Map<String, String> params) {
        Function func = getFunctionByAddressOrName(program, params.get("function_address"), params.get("function_name"));
        if (func != null) {
            return new AddressSet(func.getBody());
        }
        Address start = optionalAddress(program, params.get("start"));
        Address end = optionalAddress(program, params.get("end"));
        if (start != null && end != null) {
            return new AddressSet(start, end);
        }
        if (start != null) {
            return new AddressSet(start, program.getMaxAddress());
        }
        return new AddressSet(program.getMinAddress(), program.getMaxAddress());
    }

    private int parseCommentType(String type) {
        String normalized = lower(type);
        if (normalized == null || normalized.isEmpty() || normalized.equals("eol")) return CodeUnit.EOL_COMMENT;
        switch (normalized) {
            case "plate": return CodeUnit.PLATE_COMMENT;
            case "pre": return CodeUnit.PRE_COMMENT;
            case "post": return CodeUnit.POST_COMMENT;
            case "repeatable": return CodeUnit.REPEATABLE_COMMENT;
            case "eol": return CodeUnit.EOL_COMMENT;
            default: throw new IllegalArgumentException("unknown comment type: " + type);
        }
    }

    private SourceType parseSourceType(String value) {
        String normalized = lower(value);
        if (normalized == null || normalized.isEmpty() || normalized.equals("user") || normalized.equals("user_defined")) {
            return SourceType.USER_DEFINED;
        }
        switch (normalized) {
            case "default": return SourceType.DEFAULT;
            case "analysis": return SourceType.ANALYSIS;
            case "imported": return SourceType.IMPORTED;
            default: return SourceType.USER_DEFINED;
        }
    }

    private RefType parseRefType(String value) {
        String normalized = lower(value);
        if (normalized == null || normalized.isEmpty() || normalized.equals("data")) return RefType.DATA;
        switch (normalized) {
            case "read": return RefType.READ;
            case "write": return RefType.WRITE;
            case "read_write":
            case "readwrite": return RefType.READ_WRITE;
            case "read_ind": return RefType.READ_IND;
            case "write_ind": return RefType.WRITE_IND;
            case "read_write_ind":
            case "readwrite_ind": return RefType.READ_WRITE_IND;
            case "param": return RefType.PARAM;
            case "external":
            case "external_ref": return RefType.EXTERNAL_REF;
            case "call":
            case "unconditional_call": return RefType.UNCONDITIONAL_CALL;
            case "conditional_call": return RefType.CONDITIONAL_CALL;
            case "jump":
            case "unconditional_jump": return RefType.UNCONDITIONAL_JUMP;
            case "conditional_jump": return RefType.CONDITIONAL_JUMP;
            case "computed_jump": return RefType.COMPUTED_JUMP;
            case "computed_call": return RefType.COMPUTED_CALL;
            default: return RefType.DATA;
        }
    }

    private Namespace resolveNamespace(Program program, String namespacePath, boolean required) {
        if (namespacePath == null || namespacePath.isEmpty() || namespacePath.equals("global")) {
            if (required) throw new IllegalArgumentException("namespace is required");
            return program.getGlobalNamespace();
        }
        String normalized = namespacePath.replace("::", "/");
        String[] parts = normalized.split("/");
        Namespace current = program.getGlobalNamespace();
        SymbolTable symbols = program.getSymbolTable();
        for (String part : parts) {
            if (part == null || part.isEmpty()) continue;
            Namespace next = symbols.getNamespace(part, current);
            if (next == null) {
                if (required) throw new IllegalArgumentException("namespace not found: " + namespacePath);
                throw new IllegalArgumentException("parent namespace not found: " + namespacePath);
            }
            current = next;
        }
        return current;
    }

    private DataType resolveDataTypePath(DataTypeManager dtm, String path) {
        if (path == null || path.isEmpty()) return null;
        DataType dt = dtm.getDataType(path);
        if (dt != null) return dt;
        dt = dtm.findDataType(path);
        if (dt != null) return dt;
        return findDataTypeByNameInAllCategories(dtm, path);
    }

    private String withDataTypeTransaction(Program program, String name, JsonSupplier supplier) {
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        final Object[] result = new Object[1];
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(name);
                try {
                    result[0] = supplier.get();
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, name, e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError(name + " thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk(result[0]) : jsonError(err.toString());
    }

    private CategoryPath categoryPath(String category) {
        if (category == null || category.isEmpty() || category.equals("/")) {
            return CategoryPath.ROOT;
        }
        return new CategoryPath(category.startsWith("/") ? category : "/" + category);
    }

    private DataType requireDataType(Program program, String path) {
        DataType dt = resolveDataTypePath(program.getDataTypeManager(), required(path, "path"));
        if (dt == null) throw new IllegalArgumentException("data type not found: " + path);
        return dt;
    }

    private Structure requireStructure(Program program, String path) {
        DataType dt = requireDataType(program, path);
        if (!(dt instanceof Structure)) throw new IllegalArgumentException("not a structure: " + path);
        return (Structure) dt;
    }

    private DataTypeComponent structComponentFromParams(Structure structure, Map<String, String> params) {
        int ordinal = parseIntOrDefault(params.get("ordinal"), -1);
        if (ordinal >= 0) return structure.getComponent(ordinal);
        int offset = parseIntOrDefault(params.get("offset"), Integer.MIN_VALUE);
        if (offset != Integer.MIN_VALUE) {
            DataTypeComponent component = structure.getComponentAt(offset);
            if (component != null) return component;
            component = structure.getComponentContaining(offset);
            if (component != null) return component;
        }
        String fieldName = params.get("field_name");
        if (fieldName != null && !fieldName.isEmpty()) {
            DataTypeComponent component = structure.findComponent(fieldName);
            if (component != null) return component;
        }
        throw new IllegalArgumentException("structure field not found");
    }

    private Function functionFromParams(Program program, Map<String, String> params) {
        Function func = getFunctionByAddressOrName(program, params.get("function_address"), params.get("function_name"));
        if (func == null && params.get("address") != null) {
            func = getFunctionByAddressOrName(program, params.get("address"), null);
        }
        if (func == null) {
            throw new IllegalArgumentException("function not found");
        }
        return func;
    }

    private Parameter parameterFromParams(Function func, Map<String, String> params) {
        int ordinal = parseIntOrDefault(params.get("ordinal"), -1);
        if (ordinal >= 0) {
            Parameter parameter = func.getParameter(ordinal);
            if (parameter != null) return parameter;
        }
        String name = params.get("name");
        if (name != null && !name.isEmpty()) {
            for (Parameter parameter : func.getParameters()) {
                if (parameter.getName().equals(name)) return parameter;
            }
        }
        throw new IllegalArgumentException("parameter not found");
    }

    private Variable variableByStorage(Function func, String storage) {
        for (Variable variable : func.getAllVariables()) {
            VariableStorage variableStorage = variable.getVariableStorage();
            if (variableStorage == null) continue;
            if (variableStorage.toString().equals(storage) ||
                variableStorage.getSerializationString().equals(storage)) {
                return variable;
            }
        }
        throw new IllegalArgumentException("variable not found for storage: " + storage);
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    /**
     * Parse params from BOTH the URL query string and the POST body (if any),
     * merging them. Body params win over query params on key collisions. This
     * lets every endpoint accept GET-style query params, POST-style form bodies,
     * or a mix — callers no longer have to know which verb a given route expects.
     */
    private Map<String, String> parseAllParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        // 1. URL query string
        String query = exchange.getRequestURI().getQuery();
        if (query != null) {
            decodeFormInto(query, result);
        }
        // 2. Request body — readAllBytes() returns an empty array for GET
        // requests with no body, so this is safe to call unconditionally.
        try {
            byte[] body = exchange.getRequestBody().readAllBytes();
            if (body != null && body.length > 0) {
                String bodyStr = new String(body, StandardCharsets.UTF_8);
                decodeFormInto(bodyStr, result);
            }
        } catch (IOException e) {
            Msg.error(this, "Error reading request body", e);
        }
        return result;
    }

    private void decodeFormInto(String formEncoded, Map<String, String> out) {
        if (formEncoded == null || formEncoded.isEmpty()) return;
        for (String pair : formEncoded.split("&")) {
            if (pair.isEmpty()) continue;
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    out.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding form parameter", e);
                }
            } else if (kv.length == 1 && !kv[0].isEmpty()) {
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    out.put(key, "");
                } catch (Exception e) {
                    Msg.error(this, "Error decoding form parameter", e);
                }
            }
        }
    }

    /**
     * Backwards-compatible alias for {@link #parseAllParams}. Historically this
     * parsed only the URL query string, which caused "address is required"
     * errors when callers POST'd the body to a route that called this. Now it
     * accepts both sources transparently.
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        return parseAllParams(exchange);
    }

    /**
     * Backwards-compatible alias for {@link #parseAllParams}. Historically this
     * parsed only the POST body, which caused the same problem in reverse.
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        return parseAllParams(exchange);
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    // ----------------------------------------------------------------------------------
    // Added: write-capable / advanced endpoints
    // ----------------------------------------------------------------------------------

    private String readBytes(String addressStr, int length) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "address is required";
        if (length <= 0 || length > 65536) return "length must be 1..65536";
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            byte[] buf = new byte[length];
            int n = program.getMemory().getBytes(addr, buf);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < n; i++) sb.append(String.format("%02x", buf[i] & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "read_bytes error: " + e.getMessage();
        }
    }

    private String writeBytes(String addressStr, String hex) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty() || hex == null || hex.isEmpty())
            return "address and hex are required";
        byte[] data;
        try {
            data = parseHexBytes(hex);
        } catch (NumberFormatException e) { return "bad hex: " + e.getMessage(); }

        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("write_bytes");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getMemory().setBytes(addr, data);
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "write_bytes", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return "write_bytes thread error: " + e.getMessage(); }
        return ok.get() ? ("wrote " + data.length + " bytes at " + addressStr)
                        : ("write failed: " + err);
    }

    private String findBytes(String startStr, String hex, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (hex == null || hex.isEmpty()) return "hex required";
        String clean = hex.replaceAll("\\s", "");
        if (clean.length() % 2 != 0) return "hex must have even length";
        byte[] needle = new byte[clean.length() / 2];
        byte[] mask   = new byte[needle.length];
        try {
            for (int i = 0; i < needle.length; i++) {
                String b = clean.substring(i*2, i*2 + 2);
                if (b.equalsIgnoreCase("??") || b.equals("..")) {
                    needle[i] = 0; mask[i] = 0;
                } else {
                    needle[i] = (byte) Integer.parseInt(b, 16);
                    mask[i] = (byte) 0xff;
                }
            }
        } catch (NumberFormatException e) { return "bad hex: " + e.getMessage(); }

        try {
            Address start = (startStr != null && !startStr.isEmpty())
                ? program.getAddressFactory().getAddress(startStr)
                : program.getMinAddress();
            Memory mem = program.getMemory();
            List<String> hits = new ArrayList<>();
            Address cursor = start;
            while (hits.size() < limit) {
                Address found = mem.findBytes(cursor, needle, mask, true, new ConsoleTaskMonitor());
                if (found == null) break;
                hits.add(found.toString());
                cursor = found.add(1);
            }
            return hits.isEmpty() ? "no match" : String.join("\n", hits);
        } catch (Exception e) { return "find_bytes error: " + e.getMessage(); }
    }

    private String clearListing(String startStr, String endStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (startStr == null || startStr.isEmpty() || endStr == null || endStr.isEmpty())
            return "start and end required";
        AtomicBoolean ok = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("clear_listing");
                try {
                    Address s = program.getAddressFactory().getAddress(startStr);
                    Address e = program.getAddressFactory().getAddress(endStr);
                    program.getListing().clearCodeUnits(s, e, false);
                    ok.set(true);
                } catch (Exception ex) {
                    Msg.error(this, "clear_listing", ex);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return "thread error: " + e.getMessage(); }
        return ok.get() ? "cleared" : "clear failed";
    }

    private String disassembleAt(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "address required";
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder out = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("disassemble");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
                    boolean res = cmd.applyTo(program, new ConsoleTaskMonitor());
                    out.append("disassemble at ").append(addr).append(": ")
                       .append(res ? "ok" : ("failed — " + cmd.getStatusMsg()));
                    ok.set(res);
                } catch (Exception ex) {
                    Msg.error(this, "disassemble", ex);
                    out.append("error: ").append(ex.getMessage());
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return "thread error: " + e.getMessage(); }
        return out.toString();
    }

    /** Set the TMode context register (ARM only) at the given address.
     *  value=1 -> Thumb, value=0 -> ARM. Range is [address, address] only;
     *  call this BEFORE /disassemble at that address. */
    private String setTMode(String addressStr, String valueStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "address required";
        int value = (valueStr != null && valueStr.equals("1")) ? 1 : 0;
        ProgramContext ctx = program.getProgramContext();
        Register tmode = ctx.getRegister("TMode");
        if (tmode == null) return "TMode register not found (not an ARM program?)";
        AtomicBoolean ok = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("set_tmode");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    ctx.setValue(tmode, addr, addr, BigInteger.valueOf(value));
                    ok.set(true);
                } catch (Exception ex) {
                    Msg.error(this, "set_tmode", ex);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return "thread error: " + e.getMessage(); }
        return ok.get() ? ("TMode=" + value + " at " + addressStr) : "failed";
    }

    private String setTModeRange(String startStr, String endStr, String valueStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (startStr == null || startStr.isEmpty() || endStr == null || endStr.isEmpty())
            return "start and end required";
        int value = (valueStr != null && valueStr.equals("1")) ? 1 : 0;
        ProgramContext ctx = program.getProgramContext();
        Register tmode = ctx.getRegister("TMode");
        if (tmode == null) return "TMode register not found (not an ARM program?)";
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder out = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("set_tmode_range");
                try {
                    Address start = program.getAddressFactory().getAddress(startStr);
                    Address end = program.getAddressFactory().getAddress(endStr);
                    ctx.setValue(tmode, start, end, BigInteger.valueOf(value));
                    out.append("TMode=").append(value).append(" from ").append(start).append(" to ").append(end);
                    ok.set(true);
                } catch (Exception ex) {
                    Msg.error(this, "set_tmode_range", ex);
                    out.append("error: ").append(ex.getMessage());
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return "thread error: " + e.getMessage(); }
        return ok.get() ? out.toString() : out.toString();
    }

    private static final Set<String> LDR_PC_MNEMONICS = new HashSet<>(Arrays.asList(
        "ldr", "ldrh", "ldrsh", "ldrb", "ldrsb", "ldrd", "vldr", "vldr.32", "vldr.64",
        "ldr.w", "ldrh.w", "ldrsh.w", "ldrb.w", "ldrsb.w", "ldrd.w"
    ));

    /** True if the named LDR-style instruction can have a PC-relative literal operand. */
    private static boolean isLdrLikeMnemonic(String mnem) {
        if (mnem == null) return false;
        String m = mnem.toLowerCase();
        if (LDR_PC_MNEMONICS.contains(m)) return true;
        return m.startsWith("ldr") || m.startsWith("vldr");
    }

    /** Extract a PC-relative literal target from a single LDR-style instruction operand.
     *  Returns null when this operand is not a [pc, #imm] / [pc, #-imm] / literal form. */
    private Address extractPcRelativeTarget(Program program, Instruction instr, int opIndex,
                                            boolean isThumb) {
        Object[] objs = instr.getOpObjects(opIndex);
        if (objs == null || objs.length == 0) return null;
        boolean hasPc = false;
        long scalarVal = 0;
        boolean hasScalar = false;
        Address literalAddr = null;
        for (Object o : objs) {
            if (o instanceof Register) {
                String rn = ((Register) o).getName();
                if (rn != null && rn.equalsIgnoreCase("pc")) hasPc = true;
            } else if (o instanceof Scalar) {
                scalarVal = ((Scalar) o).getSignedValue();
                hasScalar = true;
            } else if (o instanceof Address) {
                literalAddr = (Address) o;
            }
        }
        long instrOff = instr.getAddress().getOffset();
        long pcVal = isThumb ? ((instrOff + 4L) & ~3L) : (instrOff + 8L);
        long targetOff;
        if (hasPc && hasScalar) {
            targetOff = pcVal + scalarVal;
        } else if (literalAddr != null) {
            // SLEIGH already resolved the literal to an absolute address. Trust it.
            return literalAddr;
        } else {
            return null;
        }
        try {
            return instr.getAddress().getNewAddress(targetOff);
        } catch (Exception e) {
            return null;
        }
    }

    /** Iterate LDR-style instructions in the requested scope and add a READ memory
     *  reference for the [pc, #imm] literal target when one is missing. Workaround
     *  for the ARM/Thumb cases where Ghidra's reference analyzers do not propagate
     *  PC-relative literal loads even when fully enabled. */
    private String propagateLdrPcRefs(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        boolean dryRun = parseBooleanFlag(params.getOrDefault("dry_run", "false"));
        int maxScan = parseIntOrDefault(params.get("max_scan"), 1_000_000);
        int limit = parseIntOrDefault(params.get("limit"), 5000);
        boolean seedPointerRefs = parseBooleanFlag(params.getOrDefault("seed_pointer_refs", "true"));
        try {
            Function scopeFunc = getFunctionByAddressOrName(program,
                params.get("function_address"), params.get("function_name"));
            Address scopeStart = optionalAddress(program, params.get("start"));
            Address scopeEnd = optionalAddress(program, params.get("end"));

            Listing listing = program.getListing();
            InstructionIterator it;
            if (scopeFunc != null) {
                it = listing.getInstructions(scopeFunc.getBody(), true);
            } else if (scopeStart != null && scopeEnd != null) {
                it = listing.getInstructions(new AddressSet(scopeStart, scopeEnd), true);
            } else if (scopeStart != null) {
                it = listing.getInstructions(scopeStart, true);
            } else {
                it = listing.getInstructions(true);
            }

            ProgramContext ctx = program.getProgramContext();
            Register tmode = ctx.getRegister("TMode");

            ReferenceManager refMgr = program.getReferenceManager();
            List<Map<String, Object>> added = new ArrayList<>();
            List<Map<String, Object>> existing = new ArrayList<>();
            int scanned = 0;
            int candidates = 0;
            int skippedBadTarget = 0;
            int pointerCandidates = 0;
            int pointerRefsAddedFromInstr = 0;
            int pointerRefsAddedFromPool = 0;
            int ptrSize = program.getDefaultPointerSize();

            AtomicBoolean txOk = new AtomicBoolean(false);
            int tx = dryRun ? -1 : program.startTransaction("propagate_ldr_pc_refs");
            try {
                while (it.hasNext() && scanned < maxScan) {
                    Instruction instr = it.next();
                    scanned++;
                    if (!isLdrLikeMnemonic(instr.getMnemonicString())) continue;

                    boolean isThumb = false;
                    if (tmode != null) {
                        try {
                            RegisterValue rv = ctx.getRegisterValue(tmode, instr.getAddress());
                            if (rv != null && rv.hasValue() &&
                                rv.getUnsignedValue() != null &&
                                rv.getUnsignedValue().signum() != 0) {
                                isThumb = true;
                            }
                        } catch (Exception ignore) {}
                    }

                    for (int i = 0; i < instr.getNumOperands(); i++) {
                        Address target = extractPcRelativeTarget(program, instr, i, isThumb);
                        if (target == null) continue;
                        candidates++;
                        if (!program.getMemory().contains(target)) {
                            skippedBadTarget++;
                            continue;
                        }

                        Reference existingRef = null;
                        for (Reference r : instr.getReferencesFrom()) {
                            if (target.equals(r.getToAddress())) {
                                existingRef = r;
                                break;
                            }
                        }

                        // Read the pointer value at `target` (the constant-pool slot).
                        Long pv = null;
                        if (ptrSize > 0 && program.getMemory().getBlock(target) != null) {
                            try {
                                byte[] buf = new byte[ptrSize];
                                int read = program.getMemory().getBytes(target, buf);
                                if (read == ptrSize) {
                                    long v = 0;
                                    for (int b = 0; b < ptrSize; b++) {
                                        v |= (((long) buf[b]) & 0xff) << (8 * b);
                                    }
                                    pv = v;
                                }
                            } catch (Exception ignore) {}
                        }

                        // Resolve pv as a candidate pointer target in default address space.
                        Address ptrTarget = null;
                        if (seedPointerRefs && pv != null && pv != 0L) {
                            try {
                                Address candidate = program.getAddressFactory()
                                    .getDefaultAddressSpace().getAddress(pv);
                                if (candidate != null
                                    && program.getMemory().contains(candidate)
                                    && !candidate.equals(target)
                                    && !candidate.equals(instr.getAddress())) {
                                    ptrTarget = candidate;
                                }
                            } catch (Exception ignore) {}
                        }
                        if (ptrTarget != null) pointerCandidates++;

                        boolean ldrPtrRefSeeded = false;
                        boolean poolPtrRefSeeded = false;
                        if (ptrTarget != null) {
                            boolean ldrAlreadyHasPtrRef = false;
                            for (Reference r : instr.getReferencesFrom()) {
                                if (ptrTarget.equals(r.getToAddress())) {
                                    ldrAlreadyHasPtrRef = true;
                                    break;
                                }
                            }
                            boolean poolAlreadyHasPtrRef = false;
                            for (Reference r : refMgr.getReferencesFrom(target)) {
                                if (ptrTarget.equals(r.getToAddress())) {
                                    poolAlreadyHasPtrRef = true;
                                    break;
                                }
                            }
                            if (!dryRun) {
                                if (!ldrAlreadyHasPtrRef) {
                                    try {
                                        refMgr.addMemoryReference(instr.getAddress(),
                                            ptrTarget, RefType.DATA, SourceType.ANALYSIS, i);
                                        ldrPtrRefSeeded = true;
                                        pointerRefsAddedFromInstr++;
                                    } catch (Exception ignore) {}
                                }
                                if (!poolAlreadyHasPtrRef) {
                                    try {
                                        refMgr.addMemoryReference(target, ptrTarget,
                                            RefType.DATA, SourceType.ANALYSIS, 0);
                                        poolPtrRefSeeded = true;
                                        pointerRefsAddedFromPool++;
                                    } catch (Exception ignore) {}
                                }
                            }
                        }

                        if (existingRef != null) {
                            Map<String, Object> e = new LinkedHashMap<>();
                            e.put("from", instr.getAddress().toString());
                            e.put("to", target.toString());
                            e.put("operand", existingRef.getOperandIndex());
                            e.put("type", existingRef.getReferenceType().getName());
                            if (pv != null) {
                                e.put("pointer_value",
                                    String.format("0x%0" + (ptrSize * 2) + "x", pv));
                            }
                            if (ptrTarget != null) {
                                e.put("pointer_target", ptrTarget.toString());
                                e.put("pointer_ref_from_instr_seeded", ldrPtrRefSeeded);
                                e.put("pointer_ref_from_pool_seeded", poolPtrRefSeeded);
                            }
                            existing.add(e);
                            continue;
                        }

                        Map<String, Object> entry = new LinkedHashMap<>();
                        entry.put("from", instr.getAddress().toString());
                        entry.put("mnemonic", instr.getMnemonicString());
                        entry.put("operand", i);
                        entry.put("thumb", isThumb);
                        entry.put("to", target.toString());
                        if (pv != null) {
                            entry.put("pointer_value",
                                String.format("0x%0" + (ptrSize * 2) + "x", pv));
                        }
                        if (ptrTarget != null) {
                            entry.put("pointer_target", ptrTarget.toString());
                            entry.put("pointer_ref_from_instr_seeded", ldrPtrRefSeeded);
                            entry.put("pointer_ref_from_pool_seeded", poolPtrRefSeeded);
                        }
                        if (!dryRun) {
                            try {
                                refMgr.addMemoryReference(instr.getAddress(), target,
                                    RefType.READ, SourceType.ANALYSIS, i);
                                entry.put("added", true);
                            } catch (Exception ex) {
                                entry.put("added", false);
                                entry.put("error", ex.getMessage());
                            }
                        } else {
                            entry.put("added", false);
                        }
                        added.add(entry);
                        if (added.size() >= limit) break;
                    }
                    if (added.size() >= limit) break;
                }
                txOk.set(true);
            } finally {
                if (tx >= 0) program.endTransaction(tx, txOk.get());
            }

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("scanned_instructions", scanned);
            out.put("ldr_pc_candidates", candidates);
            out.put("skipped_invalid_target", skippedBadTarget);
            out.put("added_count", added.size());
            out.put("already_present_count", existing.size());
            out.put("seed_pointer_refs", seedPointerRefs);
            out.put("pointer_candidates", pointerCandidates);
            out.put("pointer_refs_added_from_instr", pointerRefsAddedFromInstr);
            out.put("pointer_refs_added_from_pool", pointerRefsAddedFromPool);
            out.put("dry_run", dryRun);
            out.put("limit_hit", added.size() >= limit);
            out.put("added", added);
            return jsonOk(out);
        } catch (Exception e) {
            return jsonError("propagate_ldr_pc_refs error: " + e.getMessage());
        }
    }

    /** Read a pointer-sized value at {@code addr} (little-endian assumed for ARM). */
    private long readPointerValue(Program program, Address addr) throws MemoryAccessException {
        int ptrSize = program.getDefaultPointerSize();
        byte[] buf = new byte[ptrSize];
        int read = program.getMemory().getBytes(addr, buf);
        if (read != ptrSize) {
            throw new MemoryAccessException("short read at " + addr);
        }
        long v = 0;
        for (int b = 0; b < ptrSize; b++) {
            v |= (((long) buf[b]) & 0xff) << (8 * b);
        }
        return v;
    }

    /** Read a function-pointer entry at {@code pointer_address}, mask the Thumb-bit,
     *  set TMode accordingly at the target, clear any wrong-mode disassembly, then
     *  disassemble and create a function at the target. Workaround for Ghidra not
     *  propagating the Thumb bit when a constant-pool entry is interpreted as a
     *  function pointer. */
    private String createFunctionFromPointer(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        String pointerStr = params.get("pointer_address");
        if (pointerStr == null || pointerStr.isEmpty()) {
            pointerStr = params.get("address");
        }
        if (pointerStr == null || pointerStr.isEmpty()) {
            return jsonError("pointer_address is required");
        }
        String forceMode = params.get("force_mode"); // "thumb", "arm", or null
        String name = params.get("name");
        boolean createPointerData = parseBooleanFlag(params.getOrDefault("create_pointer_data", "true"));
        boolean addReference = parseBooleanFlag(params.getOrDefault("add_reference", "true"));

        ProgramContext ctx = program.getProgramContext();
        Register tmode = ctx.getRegister("TMode");
        if (tmode == null) {
            return jsonError("TMode register not found (not an ARM program?)");
        }
        try {
            Address pointerAddr = parseAddress(program, pointerStr);
            long raw = readPointerValue(program, pointerAddr);
            boolean isThumb;
            if (forceMode != null && !forceMode.isEmpty()) {
                String fm = forceMode.toLowerCase();
                if (fm.equals("thumb") || fm.equals("1")) isThumb = true;
                else if (fm.equals("arm") || fm.equals("0")) isThumb = false;
                else return jsonError("force_mode must be 'thumb' or 'arm'");
            } else {
                isThumb = (raw & 1L) != 0;
            }
            long targetOff = isThumb ? (raw & ~1L) : raw;
            Address target = pointerAddr.getNewAddress(targetOff);
            if (!program.getMemory().contains(target)) {
                return jsonError(String.format(
                    "pointer 0x%x at %s does not resolve to loaded memory",
                    raw, pointerAddr));
            }

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("pointer_address", pointerAddr.toString());
            out.put("raw_pointer_value", String.format("0x%x", raw));
            out.put("thumb", isThumb);
            out.put("target", target.toString());

            AtomicBoolean ok = new AtomicBoolean(false);
            StringBuilder note = new StringBuilder();
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("create_function_from_pointer");
                try {
                    Listing listing = program.getListing();
                    Instruction existingInstr = listing.getInstructionAt(target);
                    boolean clearedWrongMode = false;
                    if (existingInstr != null) {
                        RegisterValue rv = ctx.getRegisterValue(tmode, target);
                        boolean instrIsThumb = rv != null && rv.hasValue() &&
                            rv.getUnsignedValue() != null &&
                            rv.getUnsignedValue().signum() != 0;
                        if (instrIsThumb != isThumb) {
                            Function existingFn = program.getFunctionManager().getFunctionAt(target);
                            if (existingFn != null) {
                                program.getFunctionManager().removeFunction(target);
                            }
                            Address endAddr = existingInstr.getMaxAddress();
                            listing.clearCodeUnits(target, endAddr, false);
                            clearedWrongMode = true;
                        }
                    }
                    note.append("cleared_wrong_mode=").append(clearedWrongMode);

                    ctx.setValue(tmode, target, target,
                        BigInteger.valueOf(isThumb ? 1 : 0));

                    DisassembleCommand cmd = new DisassembleCommand(target, null, true);
                    boolean dres = cmd.applyTo(program, new ConsoleTaskMonitor());
                    note.append(", disassemble=").append(dres);
                    if (!dres) {
                        note.append(" (").append(cmd.getStatusMsg()).append(")");
                    }

                    FunctionManager fm = program.getFunctionManager();
                    Function f = fm.getFunctionAt(target);
                    if (f == null) {
                        CreateFunctionCmd fcmd = new CreateFunctionCmd(target);
                        boolean fres = fcmd.applyTo(program, new ConsoleTaskMonitor());
                        note.append(", create_function=").append(fres);
                        if (fres) f = fm.getFunctionAt(target);
                    } else {
                        note.append(", create_function=already_exists");
                    }
                    if (f != null && name != null && !name.isEmpty()) {
                        try {
                            f.setName(name, SourceType.USER_DEFINED);
                            note.append(", named=").append(name);
                        } catch (Exception e) {
                            note.append(", name_failed=").append(e.getMessage());
                        }
                    }
                    if (f != null) {
                        out.put("function", f.getEntryPoint().toString());
                        out.put("function_name", f.getName());
                    }

                    if (addReference) {
                        boolean haveRef = false;
                        for (Reference r : program.getReferenceManager()
                                .getReferencesFrom(pointerAddr)) {
                            if (target.equals(r.getToAddress())) { haveRef = true; break; }
                        }
                        if (!haveRef) {
                            try {
                                program.getReferenceManager().addMemoryReference(
                                    pointerAddr, target,
                                    f != null ? RefType.COMPUTED_CALL : RefType.DATA,
                                    SourceType.ANALYSIS, 0);
                                note.append(", ref_added");
                            } catch (Exception e) {
                                note.append(", ref_failed=").append(e.getMessage());
                            }
                        }
                    }

                    if (createPointerData) {
                        Data existingData = listing.getDataAt(pointerAddr);
                        if (existingData == null || !existingData.isDefined()) {
                            try {
                                listing.clearCodeUnits(pointerAddr,
                                    pointerAddr.add(program.getDefaultPointerSize() - 1L),
                                    false);
                                listing.createData(pointerAddr, PointerDataType.dataType,
                                    program.getDefaultPointerSize());
                                note.append(", pointer_data_created");
                            } catch (Exception e) {
                                note.append(", pointer_data_failed=").append(e.getMessage());
                            }
                        }
                    }
                    ok.set(true);
                } catch (Exception ex) {
                    Msg.error(this, "create_function_from_pointer", ex);
                    note.append(", error=").append(ex.getMessage());
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
            out.put("status", note.toString());
            return ok.get() ? jsonOk(out) : jsonError(note.toString());
        } catch (Exception e) {
            return jsonError("create_function_from_pointer error: " + e.getMessage());
        }
    }

    /** Walk a range one pointer-sized step at a time, treat each word as a function
     *  pointer, and create a Thumb/ARM function at each resolved target. Stops on
     *  the first entry that does not look like a code pointer (zero, out of memory,
     *  or — when {@code require_executable=true} — not in an executable block). */
    private String scanThumbPointerTable(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        String startStr = params.get("start");
        String endStr = params.get("end");
        int maxEntries = parseIntOrDefault(params.get("max_entries"), 256);
        boolean requireExec = parseBooleanFlag(params.getOrDefault("require_executable", "true"));
        boolean stopOnInvalid = parseBooleanFlag(params.getOrDefault("stop_on_invalid", "true"));
        boolean createFunctions = parseBooleanFlag(params.getOrDefault("create_functions", "true"));
        if (startStr == null || startStr.isEmpty()) return jsonError("start is required");

        try {
            Address start = parseAddress(program, startStr);
            Address end = (endStr != null && !endStr.isEmpty()) ? parseAddress(program, endStr) : null;
            int ptrSize = program.getDefaultPointerSize();
            List<Map<String, Object>> entries = new ArrayList<>();
            Address cursor = start;
            int created = 0;
            int skipped = 0;
            for (int i = 0; i < maxEntries; i++) {
                if (end != null && cursor.compareTo(end) > 0) break;
                if (!program.getMemory().contains(cursor)) break;
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("pointer_address", cursor.toString());
                long raw;
                try {
                    raw = readPointerValue(program, cursor);
                } catch (MemoryAccessException e) {
                    entry.put("status", "read_error: " + e.getMessage());
                    entries.add(entry);
                    break;
                }
                entry.put("raw_pointer_value", String.format("0x%x", raw));
                if (raw == 0L) {
                    entry.put("status", "zero");
                    entries.add(entry);
                    if (stopOnInvalid) break;
                    cursor = cursor.add(ptrSize);
                    continue;
                }
                boolean isThumb = (raw & 1L) != 0;
                long targetOff = isThumb ? (raw & ~1L) : raw;
                Address target;
                try {
                    target = cursor.getNewAddress(targetOff);
                } catch (Exception e) {
                    entry.put("status", "bad_target");
                    entries.add(entry);
                    if (stopOnInvalid) break;
                    cursor = cursor.add(ptrSize);
                    continue;
                }
                if (!program.getMemory().contains(target)) {
                    entry.put("status", "target_not_in_memory");
                    entries.add(entry);
                    if (stopOnInvalid) break;
                    cursor = cursor.add(ptrSize);
                    continue;
                }
                MemoryBlock blk = program.getMemory().getBlock(target);
                if (requireExec && (blk == null || !blk.isExecute())) {
                    entry.put("status", "target_not_executable");
                    entries.add(entry);
                    if (stopOnInvalid) break;
                    cursor = cursor.add(ptrSize);
                    continue;
                }
                entry.put("thumb", isThumb);
                entry.put("target", target.toString());

                if (createFunctions) {
                    Map<String, String> sub = new LinkedHashMap<>();
                    sub.put("pointer_address", cursor.toString());
                    String sres = createFunctionFromPointer(sub);
                    entry.put("create_result", sres);
                    if (sres.contains("\"ok\":true")) created++;
                    else skipped++;
                } else {
                    entry.put("status", "dry");
                }
                entries.add(entry);
                cursor = cursor.add(ptrSize);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("start", start.toString());
            out.put("end", end != null ? end.toString() : null);
            out.put("pointer_size", ptrSize);
            out.put("entry_count", entries.size());
            out.put("created", created);
            out.put("skipped", skipped);
            out.put("entries", entries);
            return jsonOk(out);
        } catch (Exception e) {
            return jsonError("scan_thumb_pointer_table error: " + e.getMessage());
        }
    }

    private String createFunctionAt(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "address required";
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder out = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("create_function");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    FunctionManager fm = program.getFunctionManager();
                    Function existing = fm.getFunctionAt(addr);
                    Function f;
                    if (existing != null) {
                        f = existing;
                        out.append("already exists");
                    } else {
                        f = fm.createFunction(name, addr,
                                new AddressSet(addr, addr),
                                SourceType.USER_DEFINED);
                        out.append("created");
                    }
                    if (f != null && name != null && !name.isEmpty()) {
                        f.setName(name, SourceType.USER_DEFINED);
                    }
                    ok.set(true);
                } catch (Exception ex) {
                    Msg.error(this, "create_function", ex);
                    out.append("error: ").append(ex.getMessage());
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return "thread error: " + e.getMessage(); }
        return out.toString();
    }

    private String deleteFunctionAt(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "address required";
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder out = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("delete_function");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Function f = getFunctionForAddress(program, addr);
                    if (f == null) {
                        out.append("no function at or containing ").append(addr);
                        return;
                    }
                    Address entry = f.getEntryPoint();
                    boolean removed = program.getFunctionManager().removeFunction(entry);
                    out.append(removed ? "deleted function at " : "failed to delete function at ").append(entry);
                    ok.set(removed);
                } catch (Exception ex) {
                    Msg.error(this, "delete_function", ex);
                    out.append("error: ").append(ex.getMessage());
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return "thread error: " + e.getMessage(); }
        return out.toString();
    }

    // ----------------------------------------------------------------------------------
    // Function body repair
    // ----------------------------------------------------------------------------------

    private List<long[]> parseRangeList(Map<String, String> params) {
        List<long[]> ranges = new ArrayList<>();
        String single = params.get("ranges");
        if (single != null && !single.isEmpty()) {
            for (String part : single.split("[,;]")) {
                String[] se = part.split("[-:]", 2);
                if (se.length == 2) {
                    ranges.add(new long[] { Long.decode(se[0].trim()), Long.decode(se[1].trim()) });
                }
            }
            return ranges;
        }
        String start = params.get("start");
        String end = params.get("end");
        if (start != null && !start.isEmpty() && end != null && !end.isEmpty()) {
            ranges.add(new long[] { Long.decode(start.trim()), Long.decode(end.trim()) });
        }
        return ranges;
    }

    private AddressSet rangesToAddressSet(Program program, List<long[]> ranges) {
        AddressSet set = new AddressSet();
        for (long[] r : ranges) {
            Address s = program.getAddressFactory().getDefaultAddressSpace().getAddress(r[0]);
            Address e = program.getAddressFactory().getDefaultAddressSpace().getAddress(r[1]);
            if (s.compareTo(e) > 0) { Address tmp = s; s = e; e = tmp; }
            set.addRange(s, e);
        }
        return set;
    }

    private Map<String, Object> functionBodySummary(Function func) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("entry", func.getEntryPoint().toString());
        data.put("name", func.getName());
        data.put("body_size", func.getBody().getNumAddresses());
        List<Object> ranges = new ArrayList<>();
        for (AddressRange r : func.getBody()) {
            Map<String, Object> rm = new LinkedHashMap<>();
            rm.put("start", r.getMinAddress().toString());
            rm.put("end", r.getMaxAddress().toString());
            rm.put("length", r.getLength());
            ranges.add(rm);
        }
        data.put("ranges", ranges);
        return data;
    }

    private String createFunctionRange(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        final Map<String, Object> result = new LinkedHashMap<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("create_function_range");
                try {
                    Address entry = parseAddress(program, required(params.get("entry"), "entry"));
                    List<long[]> rangeList = parseRangeList(params);
                    if (rangeList.isEmpty()) {
                        throw new IllegalArgumentException("at least one range required (start+end or ranges)");
                    }
                    AddressSet body = rangesToAddressSet(program, rangeList);
                    if (!body.contains(entry)) {
                        throw new IllegalArgumentException("entry " + entry + " must lie inside the supplied range");
                    }
                    String name = params.get("name");
                    SourceType source = parseSourceType(params.get("source"));
                    FunctionManager fm = program.getFunctionManager();
                    Function existing = fm.getFunctionAt(entry);
                    if (existing != null) {
                        existing.setBody(body);
                        if (name != null && !name.isEmpty()) existing.setName(name, source);
                        result.put("status", "updated");
                        result.putAll(functionBodySummary(existing));
                    } else {
                        Function created = fm.createFunction(name, entry, body, source);
                        if (created == null) throw new IllegalArgumentException("createFunction returned null");
                        result.put("status", "created");
                        result.putAll(functionBodySummary(created));
                    }
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "create_function_range", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return jsonError("create_function_range thread error: " + e.getMessage()); }
        return ok.get() ? jsonOk(result) : jsonError(err.toString());
    }

    private String setFunctionBody(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        final Map<String, Object> result = new LinkedHashMap<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("set_function_body");
                try {
                    Function func = functionFromParams(program, params);
                    List<long[]> rangeList = parseRangeList(params);
                    if (rangeList.isEmpty()) {
                        throw new IllegalArgumentException("at least one range required (start+end or ranges)");
                    }
                    AddressSet body = rangesToAddressSet(program, rangeList);
                    if (!body.contains(func.getEntryPoint())) {
                        throw new IllegalArgumentException("entry " + func.getEntryPoint() + " must lie inside the new body");
                    }
                    func.setBody(body);
                    result.putAll(functionBodySummary(func));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "set_function_body", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return jsonError("set_function_body thread error: " + e.getMessage()); }
        return ok.get() ? jsonOk(result) : jsonError(err.toString());
    }

    private String addFunctionBodyRange(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        final Map<String, Object> result = new LinkedHashMap<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("add_function_body_range");
                try {
                    Function func = functionFromParams(program, params);
                    List<long[]> rangeList = parseRangeList(params);
                    if (rangeList.isEmpty()) {
                        throw new IllegalArgumentException("at least one range required");
                    }
                    AddressSet body = new AddressSet(func.getBody());
                    body.add(rangesToAddressSet(program, rangeList));
                    func.setBody(body);
                    result.putAll(functionBodySummary(func));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "add_function_body_range", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return jsonError("add_function_body_range thread error: " + e.getMessage()); }
        return ok.get() ? jsonOk(result) : jsonError(err.toString());
    }

    private String removeFunctionBodyRange(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        final Map<String, Object> result = new LinkedHashMap<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("remove_function_body_range");
                try {
                    Function func = functionFromParams(program, params);
                    List<long[]> rangeList = parseRangeList(params);
                    if (rangeList.isEmpty()) {
                        throw new IllegalArgumentException("at least one range required");
                    }
                    AddressSet body = new AddressSet(func.getBody());
                    AddressSet remove = rangesToAddressSet(program, rangeList);
                    if (remove.contains(func.getEntryPoint())) {
                        throw new IllegalArgumentException("cannot remove the entry point from the body");
                    }
                    body.delete(remove);
                    if (!body.contains(func.getEntryPoint())) {
                        throw new IllegalArgumentException("resulting body would not contain entry point");
                    }
                    func.setBody(body);
                    result.putAll(functionBodySummary(func));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "remove_function_body_range", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return jsonError("remove_function_body_range thread error: " + e.getMessage()); }
        return ok.get() ? jsonOk(result) : jsonError(err.toString());
    }

    private String repairFunctionBody(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        final Map<String, Object> result = new LinkedHashMap<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("repair_function_body");
                try {
                    Function func = functionFromParams(program, params);
                    TaskMonitor monitor = new ConsoleTaskMonitor();
                    boolean changed = CreateFunctionCmd.fixupFunctionBody(program, func, monitor);
                    result.put("changed", changed);
                    result.putAll(functionBodySummary(func));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "repair_function_body", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return jsonError("repair_function_body thread error: " + e.getMessage()); }
        return ok.get() ? jsonOk(result) : jsonError(err.toString());
    }

    // ----------------------------------------------------------------------------------
    // Unions
    // ----------------------------------------------------------------------------------

    private Union requireUnion(Program program, String path) {
        DataType dt = requireDataType(program, path);
        if (!(dt instanceof Union)) throw new IllegalArgumentException("not a union: " + path);
        return (Union) dt;
    }

    private DataTypeComponent unionComponentFromParams(Union union, Map<String, String> params) {
        int ordinal = parseIntOrDefault(params.get("ordinal"), -1);
        if (ordinal >= 0 && ordinal < union.getNumComponents()) {
            return union.getComponent(ordinal);
        }
        String fieldName = params.get("field_name");
        if (fieldName != null && !fieldName.isEmpty()) {
            for (DataTypeComponent c : union.getComponents()) {
                if (fieldName.equals(c.getFieldName())) return c;
            }
        }
        throw new IllegalArgumentException("union field not found");
    }

    private Map<String, Object> unionToMap(Union union) {
        Map<String, Object> map = dataTypeToMap(union, false);
        map.put("component_count", union.getNumComponents());
        map.put("alignment", union.getAlignment());
        List<Object> fields = new ArrayList<>();
        for (DataTypeComponent c : union.getComponents()) {
            fields.add(dataTypeComponentToMap(c));
        }
        map.put("fields", fields);
        return map;
    }

    private String createUnion(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "create_union", () -> {
            UnionDataType union = new UnionDataType(
                categoryPath(params.get("category")),
                required(params.get("name"), "name"),
                program.getDataTypeManager());
            DataType added = program.getDataTypeManager().addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);
            return dataTypeToMap(added, true);
        });
    }

    private String deleteUnion(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "delete_union", () -> {
            Union union = requireUnion(program, params.get("path"));
            boolean removed = program.getDataTypeManager().remove(union);
            if (!removed) throw new IllegalArgumentException("union was not removed");
            return "union deleted";
        });
    }

    private String addUnionField(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "add_union_field", () -> {
            Union union = requireUnion(program, params.get("path"));
            DataType fieldType = requireDataType(program, params.get("type_path"));
            int length = parseIntOrDefault(params.get("length"), fieldType.getLength());
            DataTypeComponent component = union.add(
                fieldType,
                length,
                params.get("field_name"),
                params.get("comment"));
            return dataTypeComponentToMap(component);
        });
    }

    private String renameUnionField(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "rename_union_field", () -> {
            Union union = requireUnion(program, params.get("path"));
            DataTypeComponent component = unionComponentFromParams(union, params);
            component.setFieldName(required(params.get("new_name"), "new_name"));
            return dataTypeComponentToMap(component);
        });
    }

    private String setUnionFieldType(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "set_union_field_type", () -> {
            Union union = requireUnion(program, params.get("path"));
            DataTypeComponent old = unionComponentFromParams(union, params);
            DataType fieldType = requireDataType(program, params.get("type_path"));
            int length = parseIntOrDefault(params.get("length"), fieldType.getLength());
            int ordinal = old.getOrdinal();
            String fieldName = params.getOrDefault("field_name", old.getFieldName());
            String comment = params.getOrDefault("comment", old.getComment());
            union.delete(ordinal);
            DataTypeComponent component = union.insert(ordinal, fieldType, length, fieldName, comment);
            return dataTypeComponentToMap(component);
        });
    }

    private String deleteUnionField(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        return withDataTypeTransaction(program, "delete_union_field", () -> {
            Union union = requireUnion(program, params.get("path"));
            DataTypeComponent component = unionComponentFromParams(union, params);
            union.delete(component.getOrdinal());
            return unionToMap(union);
        });
    }

    // ----------------------------------------------------------------------------------
    // Data layout: clear_data, create_string, create_array
    // ----------------------------------------------------------------------------------

    private String clearData(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        final Map<String, Object> result = new LinkedHashMap<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("clear_data");
                try {
                    Address addr = parseAddress(program, required(params.get("address"), "address"));
                    int length = parseIntOrDefault(params.get("length"), 0);
                    boolean clearContext = "1".equals(params.get("clear_context"))
                        || "true".equalsIgnoreCase(params.get("clear_context"));
                    Listing listing = program.getListing();
                    Address end;
                    if (length > 0) {
                        end = addr.add(length - 1);
                    } else {
                        Data data = listing.getDefinedDataAt(addr);
                        if (data == null) data = listing.getDefinedDataContaining(addr);
                        if (data == null) throw new IllegalArgumentException("no defined data at " + addr);
                        end = data.getMaxAddress();
                        length = (int) (end.getOffset() - addr.getOffset() + 1);
                    }
                    listing.clearCodeUnits(addr, end, clearContext);
                    result.put("start", addr.toString());
                    result.put("end", end.toString());
                    result.put("length", length);
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "clear_data", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return jsonError("clear_data thread error: " + e.getMessage()); }
        return ok.get() ? jsonOk(result) : jsonError(err.toString());
    }

    private DataType stringDataTypeFor(String encoding, boolean nullTerminated) {
        String enc = encoding == null ? "ascii" : encoding.toLowerCase();
        switch (enc) {
            case "ascii":
            case "":
                return nullTerminated ? new TerminatedStringDataType() : new StringDataType();
            case "utf8":
            case "utf-8":
                return nullTerminated ? new TerminatedStringDataType() : new StringUTF8DataType();
            case "utf16":
            case "utf-16":
            case "unicode":
                return nullTerminated ? new TerminatedUnicodeDataType() : new UnicodeDataType();
            default:
                throw new IllegalArgumentException("unknown string encoding: " + encoding);
        }
    }

    private String createString(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        final Map<String, Object> result = new LinkedHashMap<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("create_string");
                try {
                    Address addr = parseAddress(program, required(params.get("address"), "address"));
                    boolean nullTerm = params.get("null_terminated") == null
                        || parseBooleanFlag(params.getOrDefault("null_terminated", "1"));
                    DataType dt = stringDataTypeFor(params.get("encoding"), nullTerm);
                    int length = parseIntOrDefault(params.get("length"), -1);
                    Listing listing = program.getListing();
                    int clearLength = length > 0 ? length : Math.max(1, dt.getLength());
                    listing.clearCodeUnits(addr, addr.add(clearLength - 1), false);
                    Data created = length > 0 ? listing.createData(addr, dt, length) : listing.createData(addr, dt);
                    result.put("data", dataToMap(program, created, addr));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "create_string", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return jsonError("create_string thread error: " + e.getMessage()); }
        return ok.get() ? jsonOk(result) : jsonError(err.toString());
    }

    private String createArrayAt(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        final Map<String, Object> result = new LinkedHashMap<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("create_array");
                try {
                    Address addr = parseAddress(program, required(params.get("address"), "address"));
                    DataType element = requireDataType(program, required(params.get("element_type_path"), "element_type_path"));
                    int count = Math.max(1, parseIntOrDefault(params.get("count"), 1));
                    int elementLen = element.getLength();
                    if (elementLen <= 0) throw new IllegalArgumentException("element type has no fixed length");
                    ArrayDataType array = new ArrayDataType(element, count, elementLen);
                    Listing listing = program.getListing();
                    listing.clearCodeUnits(addr, addr.add(array.getLength() - 1), false);
                    Data created = listing.createData(addr, array);
                    result.put("data", dataToMap(program, created, addr));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "create_array", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return jsonError("create_array thread error: " + e.getMessage()); }
        return ok.get() ? jsonOk(result) : jsonError(err.toString());
    }

    private String createLabel(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || name == null || name.isEmpty()) return "address and name required";
        AtomicBoolean ok = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("create_label");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getSymbolTable().createLabel(addr, name, SourceType.USER_DEFINED);
                    ok.set(true);
                } catch (Exception ex) {
                    Msg.error(this, "create_label", ex);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return "thread error: " + e.getMessage(); }
        return ok.get() ? "ok" : "failed";
    }

    /** Apply a simple data type at an address. type ∈ {byte, word, dword, qword, string, char[N]}. */
    private String createData(String addressStr, String type, int count) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || type == null) return "address and type required";
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder out = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("create_data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    DataType dt;
                    switch (type.toLowerCase()) {
                        case "byte":  case "u8":  dt = new ByteDataType();  break;
                        case "word":  case "u16": dt = new WordDataType();  break;
                        case "dword": case "u32": dt = new DWordDataType(); break;
                        case "qword": case "u64": dt = new QWordDataType(); break;
                        case "string": dt = new StringDataType();           break;
                        default: dt = new ByteDataType();                   break;
                    }
                    if (count > 1) {
                        dt = new ArrayDataType(dt, count, dt.getLength());
                    }
                    Listing l = program.getListing();
                    l.clearCodeUnits(addr, addr.add(dt.getLength() - 1), false);
                    l.createData(addr, dt);
                    out.append("created ").append(dt.getName()).append(" at ").append(addr);
                    ok.set(true);
                } catch (Exception ex) {
                    Msg.error(this, "create_data", ex);
                    out.append("error: ").append(ex.getMessage());
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return "thread error: " + e.getMessage(); }
        return out.toString();
    }

    private String analyzeAll() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder out = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("auto_analyze");
                try {
                    AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
                    mgr.reAnalyzeAll(null);
                    mgr.startAnalysis(new ConsoleTaskMonitor());
                    int n = program.getFunctionManager().getFunctionCount();
                    out.append("analysis complete; functions=").append(n);
                    ok.set(true);
                } catch (Exception ex) {
                    Msg.error(this, "analyze", ex);
                    out.append("error: ").append(ex.getMessage());
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return "thread error: " + e.getMessage(); }
        return out.toString();
    }

    private String setImageBase(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "address required";
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder out = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("set_image_base");
                try {
                    Address newBase = program.getAddressFactory().getAddress(addressStr);
                    program.setImageBase(newBase, true);
                    out.append("image base set to ").append(newBase);
                    ok.set(true);
                } catch (Exception ex) {
                    Msg.error(this, "set_image_base", ex);
                    out.append("error: ").append(ex.getMessage());
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return "thread error: " + e.getMessage(); }
        return out.toString();
    }

    private String createInitializedBlock(String name, String addressStr, String hex,
                                          String readStr, String writeStr, String executeStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty() || addressStr == null || addressStr.isEmpty() || hex == null)
            return "name, address, and hex required";
        byte[] data;
        try {
            data = parseHexBytes(hex);
        } catch (NumberFormatException e) { return "bad hex: " + e.getMessage(); }
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder out = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("create_initialized_block");
                try {
                    Address start = program.getAddressFactory().getAddress(addressStr);
                    ByteArrayInputStream in = new ByteArrayInputStream(data);
                    MemoryBlock block = program.getMemory().createInitializedBlock(
                        name, start, in, data.length, new ConsoleTaskMonitor(), false);
                    applyBlockPermissions(block, readStr, writeStr, executeStr);
                    out.append("created initialized block ").append(block.getName())
                       .append(" ").append(block.getStart()).append("-").append(block.getEnd())
                       .append(" (").append(data.length).append(" bytes)");
                    ok.set(true);
                } catch (Exception ex) {
                    Msg.error(this, "create_initialized_block", ex);
                    out.append("error: ").append(ex.getMessage());
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return "thread error: " + e.getMessage(); }
        return out.toString();
    }

    private String createUninitializedBlock(String name, String addressStr, long size,
                                            String readStr, String writeStr, String executeStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty() || addressStr == null || addressStr.isEmpty() || size <= 0)
            return "name, address, and positive size required";
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder out = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("create_uninitialized_block");
                try {
                    Address start = program.getAddressFactory().getAddress(addressStr);
                    MemoryBlock block = program.getMemory().createUninitializedBlock(
                        name, start, size, false);
                    applyBlockPermissions(block, readStr, writeStr, executeStr);
                    out.append("created uninitialized block ").append(block.getName())
                       .append(" ").append(block.getStart()).append("-").append(block.getEnd())
                       .append(" (").append(size).append(" bytes)");
                    ok.set(true);
                } catch (Exception ex) {
                    Msg.error(this, "create_uninitialized_block", ex);
                    out.append("error: ").append(ex.getMessage());
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return "thread error: " + e.getMessage(); }
        return out.toString();
    }

    private String removeMemoryBlock(String name, String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder out = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("remove_memory_block");
                try {
                    MemoryBlock block = getMemoryBlock(program, name, addressStr);
                    if (block == null) {
                        out.append("memory block not found");
                        return;
                    }
                    String blockName = block.getName();
                    program.getMemory().removeBlock(block, new ConsoleTaskMonitor());
                    out.append("removed memory block ").append(blockName);
                    ok.set(true);
                } catch (Exception ex) {
                    Msg.error(this, "remove_memory_block", ex);
                    out.append("error: ").append(ex.getMessage());
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return "thread error: " + e.getMessage(); }
        return out.toString();
    }

    private String setBlockPermissions(String name, String addressStr,
                                       String readStr, String writeStr, String executeStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder out = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("set_block_permissions");
                try {
                    MemoryBlock block = getMemoryBlock(program, name, addressStr);
                    if (block == null) {
                        out.append("memory block not found");
                        return;
                    }
                    applyBlockPermissions(block, readStr, writeStr, executeStr);
                    out.append("permissions for ").append(block.getName())
                       .append(": r=").append(block.isRead())
                       .append(" w=").append(block.isWrite())
                       .append(" x=").append(block.isExecute());
                    ok.set(true);
                } catch (Exception ex) {
                    Msg.error(this, "set_block_permissions", ex);
                    out.append("error: ").append(ex.getMessage());
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return "thread error: " + e.getMessage(); }
        return out.toString();
    }

    private String programInfo() {
        Program program = getCurrentProgram();
        if (program == null) {
            StringBuilder sb = new StringBuilder("No program loaded\n");
            sb.append("agent_hint=no_user_needed_to_load_binary: ")
              .append("call import_file(path) / open_program(project_path) / ")
              .append("bring_up(rom_path, ...) yourself.\n");
            sb.append("agent_hint=after_load_enable_scalar_operand_refs: ")
              .append("call enable_analyzer(name=\"Scalar Operand References\") ")
              .append("then analyze() — disabled by default, can surface 28k+ extra ")
              .append("function references on dense binaries.\n");
            return sb.toString();
        }
        StringBuilder sb = new StringBuilder();
        sb.append("name=").append(program.getName()).append("\n");
        sb.append("language=").append(program.getLanguage().getLanguageID()).append("\n");
        sb.append("compiler=").append(program.getCompilerSpec().getCompilerSpecID()).append("\n");
        sb.append("image_base=").append(program.getImageBase()).append("\n");
        sb.append("min_addr=").append(program.getMinAddress()).append("\n");
        sb.append("max_addr=").append(program.getMaxAddress()).append("\n");
        sb.append("function_count=").append(program.getFunctionManager().getFunctionCount()).append("\n");
        for (String hint : buildAgentHints(AppInfo.getActiveProject(), program)) {
            sb.append("agent_hint=").append(hint).append("\n");
        }
        return sb.toString();
    }

    private String listEndpoints() {
        StringBuilder sb = new StringBuilder();
        for (String ep : registeredEndpoints) {
            sb.append(ep).append("\n");
        }
        return sb.toString();
    }

    private String countFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("count", program.getFunctionManager().getFunctionCount());
        return jsonOk(data);
    }

    private String listMemoryBlocks(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        List<Object> items = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            Map<String, Object> b = new LinkedHashMap<>();
            b.put("name", block.getName());
            b.put("start", block.getStart().toString());
            b.put("end", block.getEnd().toString());
            b.put("size", block.getSize());
            b.put("read", block.isRead());
            b.put("write", block.isWrite());
            b.put("execute", block.isExecute());
            b.put("initialized", block.isInitialized());
            b.put("overlay", block.isOverlay());
            String type;
            try { type = block.getType().toString(); } catch (Exception e) { type = ""; }
            b.put("type", type);
            String comment = block.getComment();
            if (comment != null && !comment.isEmpty()) b.put("comment", comment);
            items.add(b);
        }
        return jsonOk(paginatedData(offset, limit, items));
    }

    /**
     * Seed functions across an address range by scanning for common ARM/Thumb
     * function-prologue byte patterns (push variants). For each detected
     * candidate, set the appropriate TMode (Thumb/ARM), run the disassembler
     * at that address, and create a function.
     *
     * Params:
     *   start, end             — address range (required; inclusive on both ends)
     *   mode                   — "thumb", "arm", or "both" (default "thumb")
     *   detect_thumb_no_lr     — also seed on Thumb `push {regs}` w/o LR (0xB4xx) (default false)
     *   max_seeds              — cap on functions created in this call (default 20000)
     *   dry_run                — if true/1 do not create anything, just report candidates
     *
     * Pattern matching (little-endian byte stream):
     *   Thumb push {…, lr}    half-word `xx B5` at 2-byte alignment
     *   Thumb push {…}        half-word `xx B4` at 2-byte alignment (optional, noisy)
     *   ARM push {…}          word `2D E9 xx xx` at 4-byte alignment (stmdb sp!, …)
     *
     * Only positions inside currently-undefined initialized executable memory
     * are considered.
     */
    private String seedFunctionsInRange(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        String startStr = params.get("start");
        String endStr = params.get("end");
        if (startStr == null || startStr.isEmpty() || endStr == null || endStr.isEmpty()) {
            return jsonError("start and end are required");
        }
        String mode = params.getOrDefault("mode", "thumb").toLowerCase();
        boolean wantThumb = mode.equals("thumb") || mode.equals("both");
        boolean wantArm = mode.equals("arm") || mode.equals("both");
        if (!wantThumb && !wantArm) return jsonError("mode must be thumb, arm, or both");
        boolean detectThumbNoLr = parseBooleanFlag(params.getOrDefault("detect_thumb_no_lr", "false"));
        boolean dryRun = parseBooleanFlag(params.getOrDefault("dry_run", "false"));
        int maxSeeds = parseIntOrDefault(params.get("max_seeds"), 20000);

        ProgramContext ctx = program.getProgramContext();
        Register tmode = ctx.getRegister("TMode");
        boolean haveTmode = tmode != null;
        if (wantThumb && !haveTmode) {
            return jsonError("TMode register not found — thumb mode requires an ARM program");
        }

        Address start, end;
        try {
            start = parseAddress(program, startStr);
            end = parseAddress(program, endStr);
        } catch (Exception e) {
            return jsonError("invalid address: " + e.getMessage());
        }
        if (start.compareTo(end) > 0) { Address t = start; start = end; end = t; }

        // Restrict to undefined, executable, initialized memory inside the range.
        AddressSet rangeSet = new AddressSet();
        rangeSet.addRange(start, end);
        AddressSet scope = new AddressSet();
        for (MemoryBlock b : program.getMemory().getBlocks()) {
            if (!b.isExecute() || !b.isInitialized()) continue;
            Address bs = b.getStart();
            Address be = b.getEnd();
            if (be.compareTo(start) < 0 || bs.compareTo(end) > 0) continue;
            Address sLo = bs.compareTo(start) < 0 ? start : bs;
            Address sHi = be.compareTo(end) > 0 ? end : be;
            scope.addRange(sLo, sHi);
        }
        AddressSetView undef;
        try {
            undef = program.getListing().getUndefinedRanges(scope, true, new ConsoleTaskMonitor());
        } catch (Exception e) {
            return jsonError("getUndefinedRanges failed: " + e.getMessage());
        }

        // First pass: collect candidates without mutating program state.
        List<long[]> thumbCandidates = new ArrayList<>(); // {addrOffset}
        List<long[]> armCandidates = new ArrayList<>();
        long scannedBytes = 0;
        Memory mem = program.getMemory();
        AddressRangeIterator rit = undef.getAddressRanges();
        outer:
        while (rit.hasNext()) {
            AddressRange r = rit.next();
            Address cur = r.getMinAddress();
            Address rEnd = r.getMaxAddress();
            long rangeLen = r.getLength();
            // Read range bytes in one go (bounded chunk to avoid OOM on huge undefined regions).
            int chunkSize = (int) Math.min(rangeLen, 1 << 20); // 1 MiB chunks
            long covered = 0;
            while (covered < rangeLen) {
                int toRead = (int) Math.min(chunkSize, rangeLen - covered);
                byte[] buf = new byte[toRead];
                Address chunkStart;
                try { chunkStart = cur.add(covered); } catch (Exception ex) { break; }
                int got;
                try { got = mem.getBytes(chunkStart, buf); } catch (Exception ex) { break; }
                if (got <= 0) break;
                // Find candidates.
                long startOffset = chunkStart.getOffset();
                // Thumb scan: half-word aligned. Require start address to be even.
                long startEven = (startOffset & 1L) == 0L ? 0L : 1L;
                if (wantThumb) {
                    for (int i = (int) startEven; i + 1 < got; i += 2) {
                        int hi = buf[i + 1] & 0xff;
                        if (hi == 0xB5 || (detectThumbNoLr && hi == 0xB4)) {
                            thumbCandidates.add(new long[]{ startOffset + i });
                            if (thumbCandidates.size() + armCandidates.size() >= maxSeeds * 4L) {
                                break outer;
                            }
                        }
                    }
                }
                // ARM scan: word aligned. start must be 4-byte aligned.
                if (wantArm) {
                    long mod = startOffset & 3L;
                    int armStart = (int) ((4L - mod) & 3L);
                    for (int i = armStart; i + 3 < got; i += 4) {
                        // stmdb sp!, {…} encoded little-endian as `xx xx 2D E9`
                        if ((buf[i + 2] & 0xff) == 0x2D && (buf[i + 3] & 0xff) == 0xE9) {
                            armCandidates.add(new long[]{ startOffset + i });
                            if (thumbCandidates.size() + armCandidates.size() >= maxSeeds * 4L) {
                                break outer;
                            }
                        }
                    }
                }
                scannedBytes += got;
                covered += got;
                if (got < toRead) break;
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("scanned_bytes", scannedBytes);
        result.put("thumb_candidates", thumbCandidates.size());
        result.put("arm_candidates", armCandidates.size());
        result.put("dry_run", dryRun);

        if (dryRun) {
            List<Object> sample = new ArrayList<>();
            int n = Math.min(50, thumbCandidates.size());
            for (int i = 0; i < n; i++) {
                Map<String, Object> e = new LinkedHashMap<>();
                e.put("address", String.format("0x%x", thumbCandidates.get(i)[0]));
                e.put("kind", "thumb");
                sample.add(e);
            }
            int m = Math.min(50 - sample.size(), armCandidates.size());
            for (int i = 0; i < m; i++) {
                Map<String, Object> e = new LinkedHashMap<>();
                e.put("address", String.format("0x%x", armCandidates.get(i)[0]));
                e.put("kind", "arm");
                sample.add(e);
            }
            result.put("sample", sample);
            return jsonOk(result);
        }

        // Second pass: create functions inside a single transaction.
        final List<Object> created = new ArrayList<>();
        final List<Object> failed = new ArrayList<>();
        final int cap = Math.min(maxSeeds, thumbCandidates.size() + armCandidates.size());
        final Program prog = program;
        final Register tmodeRef = tmode;
        AtomicBoolean ok = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = prog.startTransaction("seed_functions_in_range");
                try {
                    FunctionManager fm = prog.getFunctionManager();
                    Listing listing = prog.getListing();
                    int produced = 0;
                    // Thumb first (likely majority on GBA/ARM Thumb-heavy code).
                    for (long[] c : thumbCandidates) {
                        if (produced >= cap) break;
                        Address addr;
                        try {
                            addr = prog.getAddressFactory().getDefaultAddressSpace().getAddress(c[0]);
                        } catch (Exception e) { continue; }
                        if (fm.getFunctionAt(addr) != null) continue;
                        if (listing.getInstructionAt(addr) != null) {
                            // Already disassembled (maybe wrong mode) — skip to be safe.
                            continue;
                        }
                        try {
                            if (haveTmode) {
                                ctx.setValue(tmodeRef, addr, addr, BigInteger.ONE);
                            }
                            DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
                            boolean dres = cmd.applyTo(prog, TaskMonitor.DUMMY);
                            if (!dres) {
                                Map<String, Object> f = new LinkedHashMap<>();
                                f.put("address", addr.toString());
                                f.put("kind", "thumb");
                                f.put("reason", "disassemble_failed: " + cmd.getStatusMsg());
                                failed.add(f);
                                continue;
                            }
                            CreateFunctionCmd fcmd = new CreateFunctionCmd(addr);
                            boolean fres = fcmd.applyTo(prog, TaskMonitor.DUMMY);
                            if (fres && fm.getFunctionAt(addr) != null) {
                                Map<String, Object> e = new LinkedHashMap<>();
                                e.put("address", addr.toString());
                                e.put("kind", "thumb");
                                created.add(e);
                                produced++;
                            } else {
                                Map<String, Object> f = new LinkedHashMap<>();
                                f.put("address", addr.toString());
                                f.put("kind", "thumb");
                                f.put("reason", "create_function_failed");
                                failed.add(f);
                            }
                        } catch (Exception ex) {
                            Map<String, Object> f = new LinkedHashMap<>();
                            f.put("address", addr.toString());
                            f.put("kind", "thumb");
                            f.put("reason", ex.getMessage());
                            failed.add(f);
                        }
                    }
                    for (long[] c : armCandidates) {
                        if (produced >= cap) break;
                        Address addr;
                        try {
                            addr = prog.getAddressFactory().getDefaultAddressSpace().getAddress(c[0]);
                        } catch (Exception e) { continue; }
                        if (fm.getFunctionAt(addr) != null) continue;
                        if (listing.getInstructionAt(addr) != null) continue;
                        try {
                            if (haveTmode) {
                                ctx.setValue(tmodeRef, addr, addr, BigInteger.ZERO);
                            }
                            DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
                            boolean dres = cmd.applyTo(prog, TaskMonitor.DUMMY);
                            if (!dres) {
                                Map<String, Object> f = new LinkedHashMap<>();
                                f.put("address", addr.toString());
                                f.put("kind", "arm");
                                f.put("reason", "disassemble_failed: " + cmd.getStatusMsg());
                                failed.add(f);
                                continue;
                            }
                            CreateFunctionCmd fcmd = new CreateFunctionCmd(addr);
                            boolean fres = fcmd.applyTo(prog, TaskMonitor.DUMMY);
                            if (fres && fm.getFunctionAt(addr) != null) {
                                Map<String, Object> e = new LinkedHashMap<>();
                                e.put("address", addr.toString());
                                e.put("kind", "arm");
                                created.add(e);
                                produced++;
                            } else {
                                Map<String, Object> f = new LinkedHashMap<>();
                                f.put("address", addr.toString());
                                f.put("kind", "arm");
                                f.put("reason", "create_function_failed");
                                failed.add(f);
                            }
                        } catch (Exception ex) {
                            Map<String, Object> f = new LinkedHashMap<>();
                            f.put("address", addr.toString());
                            f.put("kind", "arm");
                            f.put("reason", ex.getMessage());
                            failed.add(f);
                        }
                    }
                    ok.set(true);
                } catch (Exception e) {
                    Msg.error(this, "seed_functions_in_range", e);
                } finally {
                    prog.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("seed_functions_in_range thread error: " + e.getMessage());
        }
        result.put("created_count", created.size());
        result.put("failed_count", failed.size());
        // Cap the size of the embedded lists to keep responses small.
        int previewCap = parseIntOrDefault(params.get("preview_limit"), 100);
        result.put("created_preview", created.size() <= previewCap ? created : created.subList(0, previewCap));
        result.put("failed_preview", failed.size() <= previewCap ? failed : failed.subList(0, previewCap));
        return jsonOk(result);
    }

    /**
     * Extract a flat fixed-stride C-string table from memory. Useful for game
     * ROMs and other binaries where names (species, moves, items, …) are
     * stored as a tightly-packed array of fixed-width null-padded strings.
     *
     * Params:
     *   base      — start address of the table (required)
     *   stride    — bytes per entry (required, > 0)
     *   count     — number of entries to read (required, > 0)
     *   encoding  — "ascii" (default), "utf8", "latin1", or "raw" (hex bytes)
     *   trim_null — trim at first 0x00 byte (default true)
     *   apply     — if true, create string data in Ghidra for each entry
     *                (transactional). Default false (read-only).
     *   preview_limit — cap on entries embedded in the response (default 1024)
     *
     * Returns: { base, stride, count, encoding, entries: [{ index, address,
     *   text, raw_hex?, length }], applied_count? }
     */
    private String stringTableAt(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");

        Address base;
        int stride, count;
        try {
            base = parseAddress(program, required(params.get("base"), "base"));
            stride = Integer.parseInt(required(params.get("stride"), "stride"));
            count = Integer.parseInt(required(params.get("count"), "count"));
        } catch (NumberFormatException e) {
            return jsonError("stride and count must be integers");
        } catch (IllegalArgumentException e) {
            return jsonError(e.getMessage());
        }
        if (stride <= 0) return jsonError("stride must be > 0");
        if (count <= 0) return jsonError("count must be > 0");
        if ((long) stride * count > 16L * 1024L * 1024L) {
            return jsonError("stride*count too large (max 16MB)");
        }
        String encoding = params.getOrDefault("encoding", "ascii").toLowerCase();
        boolean trimNull = parseBooleanFlag(params.getOrDefault("trim_null", "true"));
        boolean apply = parseBooleanFlag(params.getOrDefault("apply", "false"));
        int previewLimit = parseIntOrDefault(params.get("preview_limit"), 1024);

        java.nio.charset.Charset charset;
        boolean rawHex = false;
        switch (encoding) {
            case "ascii":   charset = StandardCharsets.US_ASCII; break;
            case "utf8":
            case "utf-8":   charset = StandardCharsets.UTF_8; break;
            case "latin1":
            case "iso-8859-1":
            case "iso8859-1": charset = StandardCharsets.ISO_8859_1; break;
            case "raw":
            case "hex":     charset = null; rawHex = true; break;
            default: return jsonError("unknown encoding: " + encoding);
        }

        long totalBytes = (long) stride * count;
        byte[] all = new byte[(int) totalBytes];
        Memory mem = program.getMemory();
        int got;
        try {
            got = mem.getBytes(base, all);
        } catch (MemoryAccessException e) {
            return jsonError("memory read failed: " + e.getMessage());
        }
        if (got < totalBytes) {
            // Truncate to actually-readable bytes; we'll still emit entries
            // covered by what we got.
            byte[] trimmed = new byte[got];
            System.arraycopy(all, 0, trimmed, 0, got);
            all = trimmed;
        }
        int readableEntries = all.length / stride;

        List<Object> entries = new ArrayList<>();
        int emitted = Math.min(count, readableEntries);
        int cap = Math.min(emitted, Math.max(0, previewLimit));
        for (int i = 0; i < cap; i++) {
            int off = i * stride;
            int textLen = stride;
            if (trimNull) {
                for (int j = 0; j < stride; j++) {
                    if (all[off + j] == 0) { textLen = j; break; }
                }
            }
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("index", i);
            Address entryAddr;
            try { entryAddr = base.add((long) i * stride); }
            catch (Exception ex) { entryAddr = null; }
            e.put("address", entryAddr != null ? entryAddr.toString() : null);
            if (rawHex) {
                StringBuilder hex = new StringBuilder(textLen * 2);
                for (int j = 0; j < textLen; j++) {
                    hex.append(String.format("%02x", all[off + j] & 0xff));
                }
                e.put("raw_hex", hex.toString());
            } else {
                String text = new String(all, off, textLen, charset);
                e.put("text", text);
            }
            e.put("length", textLen);
            entries.add(e);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("base", base.toString());
        result.put("stride", stride);
        result.put("count", count);
        result.put("readable_entries", readableEntries);
        result.put("encoding", encoding);
        result.put("entries", entries);
        if (cap < emitted) {
            result.put("truncated", true);
            result.put("preview_limit", previewLimit);
        }

        if (apply) {
            final byte[] bytes = all;
            final int writeCount = emitted;
            final boolean trim = trimNull;
            final AtomicInteger applied = new AtomicInteger(0);
            final List<String> errors = new ArrayList<>();
            final Program prog = program;
            final Address baseAddr = base;
            final int strideF = stride;
            try {
                SwingUtilities.invokeAndWait(() -> {
                    int tx = prog.startTransaction("string_table_at");
                    boolean okFlag = false;
                    try {
                        Listing listing = prog.getListing();
                        for (int i = 0; i < writeCount; i++) {
                            int off = i * strideF;
                            int textLen = strideF;
                            if (trim) {
                                for (int j = 0; j < strideF; j++) {
                                    if (bytes[off + j] == 0) { textLen = j; break; }
                                }
                            }
                            if (textLen <= 0) continue;
                            try {
                                Address a = baseAddr.add((long) i * strideF);
                                // Clear any conflicting code units across the whole stride
                                // so the apply doesn't fight existing data.
                                Address aEnd = a.add(strideF - 1);
                                listing.clearCodeUnits(a, aEnd, false);
                                // Apply a terminated ascii string with explicit length
                                // when a NUL is present, otherwise a fixed-length string.
                                DataType dt;
                                int applyLen;
                                if (trim && textLen < strideF) {
                                    dt = new TerminatedStringDataType();
                                    applyLen = textLen + 1; // include terminator
                                } else {
                                    dt = new StringDataType();
                                    applyLen = strideF;
                                }
                                listing.createData(a, dt, applyLen);
                                applied.incrementAndGet();
                            } catch (Exception ex) {
                                if (errors.size() < 16) errors.add(i + ": " + ex.getMessage());
                            }
                        }
                        okFlag = true;
                    } finally {
                        prog.endTransaction(tx, okFlag);
                    }
                });
            } catch (Exception e) {
                return jsonError("string_table_at apply thread error: " + e.getMessage());
            }
            result.put("applied_count", applied.get());
            if (!errors.isEmpty()) result.put("apply_errors", errors);
        }

        return jsonOk(result);
    }

    private byte[] parseHexBytes(String hex) {
        String clean = hex.replaceAll("\\s", "");
        if (clean.length() % 2 != 0) throw new NumberFormatException("hex must have even length");
        byte[] data = new byte[clean.length() / 2];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) Integer.parseInt(clean.substring(i*2, i*2 + 2), 16);
        }
        return data;
    }

    private MemoryBlock getMemoryBlock(Program program, String name, String addressStr) {
        if (name != null && !name.isEmpty()) {
            MemoryBlock block = program.getMemory().getBlock(name);
            if (block != null) return block;
        }
        if (addressStr != null && !addressStr.isEmpty()) {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            return program.getMemory().getBlock(addr);
        }
        return null;
    }

    private void applyBlockPermissions(MemoryBlock block, String readStr, String writeStr, String executeStr) {
        if (readStr != null && !readStr.isEmpty()) block.setRead(parseBooleanFlag(readStr));
        if (writeStr != null && !writeStr.isEmpty()) block.setWrite(parseBooleanFlag(writeStr));
        if (executeStr != null && !executeStr.isEmpty()) block.setExecute(parseBooleanFlag(executeStr));
    }

    private boolean parseBooleanFlag(String value) {
        return value.equals("1") || value.equalsIgnoreCase("true") ||
               value.equalsIgnoreCase("yes") || value.equalsIgnoreCase("on");
    }

    // ----------------------------------------------------------------------------------
    // Analysis workflow control + undefined-code discovery
    // ----------------------------------------------------------------------------------

    private List<Analyzer> getAvailableAnalyzers(Program program) {
        List<Analyzer> all = ClassSearcher.getInstances(Analyzer.class);
        List<Analyzer> result = new ArrayList<>(all.size());
        for (Analyzer a : all) {
            try {
                if (a.canAnalyze(program)) result.add(a);
            } catch (Throwable t) {
                // skip analyzers that throw on canAnalyze
            }
        }
        return result;
    }

    private Analyzer findAnalyzer(Program program, String name) {
        if (name == null) return null;
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        Analyzer direct = mgr.getAnalyzer(name);
        if (direct != null) return direct;
        for (Analyzer a : getAvailableAnalyzers(program)) {
            if (name.equals(a.getName())) return a;
        }
        return null;
    }

    private String listAnalyzers(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            String applicableStr = params.get("applicable");
            boolean onlyApplicable = applicableStr == null
                || (!"0".equals(applicableStr) && !"false".equalsIgnoreCase(applicableStr));
            Options analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
            List<Object> items = new ArrayList<>();
            List<Analyzer> source = onlyApplicable
                ? getAvailableAnalyzers(program)
                : ClassSearcher.getInstances(Analyzer.class);
            for (Analyzer a : source) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("name", a.getName());
                m.put("description", a.getDescription());
                AnalyzerType type = a.getAnalysisType();
                m.put("type", type != null ? type.toString() : null);
                AnalysisPriority p = a.getPriority();
                m.put("priority", p != null ? p.priority() : null);
                m.put("priority_name", p != null ? p.toString() : null);
                boolean canAnalyze;
                try { canAnalyze = a.canAnalyze(program); } catch (Throwable t) { canAnalyze = false; }
                m.put("can_analyze", canAnalyze);
                boolean defaultEnabled;
                try { defaultEnabled = a.getDefaultEnablement(program); } catch (Throwable t) { defaultEnabled = false; }
                m.put("default_enabled", defaultEnabled);
                m.put("supports_one_time", a.supportsOneTimeAnalysis());
                m.put("is_prototype", a.isPrototype());
                m.put("enabled", analysisOptions.getBoolean(a.getName(), defaultEnabled));
                items.add(m);
            }
            items.sort(Comparator.comparing(o -> String.valueOf(((Map<?, ?>) o).get("name"))));
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), items.size());
            return jsonOk(paginatedData(offset, limit, items));
        } catch (Exception e) {
            return jsonError("list_analyzers error: " + e.getMessage());
        }
    }

    private String getAnalyzerOptions(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            String name = required(params.get("name"), "name");
            Options analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
            Analyzer analyzer = findAnalyzer(program, name);
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("name", name);
            boolean defaultEnabled = false;
            if (analyzer != null) {
                try { defaultEnabled = analyzer.getDefaultEnablement(program); } catch (Throwable t) { }
                data.put("description", analyzer.getDescription());
                data.put("default_enabled", defaultEnabled);
            }
            data.put("enabled", analysisOptions.getBoolean(name, defaultEnabled));
            List<Object> opts = new ArrayList<>();
            if (analysisOptions.contains(name) || (analyzer != null)) {
                Options sub = analysisOptions.getOptions(name);
                for (String optName : sub.getLeafOptionNames()) {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("name", optName);
                    OptionType type = sub.getType(optName);
                    entry.put("type", type != null ? type.toString() : null);
                    entry.put("value", sub.getValueAsString(optName));
                    entry.put("default", sub.getDefaultValueAsString(optName));
                    entry.put("description", sub.getDescription(optName));
                    try { entry.put("is_default", sub.isDefaultValue(optName)); } catch (Exception ex) { entry.put("is_default", null); }
                    opts.add(entry);
                }
            }
            data.put("options", opts);
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("get_analyzer_options error: " + e.getMessage());
        }
    }

    private String setAnalyzerOption(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        final String analyzerName = required(params.get("name"), "name");
        final String optionName = params.get("option");
        final String valueStr = required(params.get("value"), "value");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        final Map<String, Object> result = new LinkedHashMap<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("set_analyzer_option");
                try {
                    Options analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
                    Options target = analysisOptions;
                    String key = analyzerName;
                    boolean topLevel = optionName == null || optionName.isEmpty();
                    if (!topLevel) {
                        target = analysisOptions.getOptions(analyzerName);
                        key = optionName;
                    }
                    OptionType type = target.getType(key);
                    if (type == null || type == OptionType.NO_TYPE) {
                        if (topLevel) {
                            type = OptionType.BOOLEAN_TYPE;
                        } else {
                            throw new IllegalArgumentException("unknown option: " + analyzerName + "." + optionName);
                        }
                    }
                    Object value = type.convertStringToObject(valueStr);
                    target.putObject(key, value);
                    result.put("analyzer", analyzerName);
                    result.put("option", topLevel ? "" : optionName);
                    result.put("type", type.toString());
                    result.put("value", target.getValueAsString(key));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "set_analyzer_option", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) {
            return jsonError("set_analyzer_option thread error: " + e.getMessage());
        }
        return ok.get() ? jsonOk(result) : jsonError(err.toString());
    }

    private String setAnalyzerEnabled(Map<String, String> params, boolean enable) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        final String name = required(params.get("name"), "name");
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        final Map<String, Object> result = new LinkedHashMap<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(enable ? "enable_analyzer" : "disable_analyzer");
                try {
                    Options analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
                    analysisOptions.setBoolean(name, enable);
                    result.put("analyzer", name);
                    result.put("enabled", analysisOptions.getBoolean(name, enable));
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, enable ? "enable_analyzer" : "disable_analyzer", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return jsonError("thread error: " + e.getMessage()); }
        return ok.get() ? jsonOk(result) : jsonError(err.toString());
    }

    private AddressSetView resolveAnalysisRange(Program program, Map<String, String> params) {
        Function func = getFunctionByAddressOrName(program,
            params.get("function_address"), params.get("function_name"));
        if (func != null) return new AddressSet(func.getBody());
        Address start = optionalAddress(program, params.get("start"));
        Address end = optionalAddress(program, params.get("end"));
        if (start != null && end != null) return new AddressSet(start, end);
        if (start != null) return new AddressSet(start, program.getMaxAddress());
        return new AddressSet(program.getMemory());
    }

    private String runAnalyzer(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        final String name = required(params.get("name"), "name");
        final Analyzer analyzer = findAnalyzer(program, name);
        if (analyzer == null) return jsonError("analyzer not found: " + name);
        if (!analyzer.supportsOneTimeAnalysis()) {
            return jsonError("analyzer does not support one-time analysis: " + name);
        }
        final AddressSetView set = resolveAnalysisRange(program, params);
        if (set.isEmpty()) return jsonError("empty address set");
        final AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("run_analyzer:" + name);
                try {
                    mgr.scheduleOneTimeAnalysis(analyzer, set);
                    mgr.startAnalysis(new ConsoleTaskMonitor());
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "run_analyzer", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return jsonError("run_analyzer thread error: " + e.getMessage()); }
        if (!ok.get()) return jsonError(err.toString());
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("analyzer", name);
        r.put("range_count", set.getNumAddressRanges());
        r.put("address_count", set.getNumAddresses());
        r.put("message_log", mgr.getMessageLog().toString());
        return jsonOk(r);
    }

    private String analyzeRange(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        final AddressSetView set = resolveAnalysisRange(program, params);
        if (set.isEmpty()) return jsonError("empty address set");
        final AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        AtomicBoolean ok = new AtomicBoolean(false);
        StringBuilder err = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("analyze_range");
                try {
                    mgr.reAnalyzeAll(set);
                    mgr.startAnalysis(new ConsoleTaskMonitor());
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                    Msg.error(this, "analyze_range", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (Exception e) { return jsonError("analyze_range thread error: " + e.getMessage()); }
        if (!ok.get()) return jsonError(err.toString());
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("range_count", set.getNumAddressRanges());
        r.put("address_count", set.getNumAddresses());
        r.put("functions_after", program.getFunctionManager().getFunctionCount());
        r.put("message_log", mgr.getMessageLog().toString());
        return jsonOk(r);
    }

    private String analyzeFunction(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        Function func = getFunctionByAddressOrName(program,
            params.get("function_address"), params.get("function_name"));
        if (func == null) {
            String addr = params.get("address");
            if (addr != null && !addr.isEmpty()) {
                func = getFunctionByAddressOrName(program, addr, null);
            }
        }
        if (func == null) return jsonError("function not found");
        Map<String, String> p = new HashMap<>(params);
        p.put("function_address", func.getEntryPoint().toString());
        return analyzeRange(p);
    }

    private String getAnalysisStatus() {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("analyzing", mgr.isAnalyzing());
            data.put("total_time_ms", mgr.getTotalTimeInMillis());
            MessageLog log = mgr.getMessageLog();
            data.put("has_messages", log != null && log.hasMessages());
            data.put("message_log", log != null ? log.toString() : "");
            String[] timed = mgr.getTimedTasks();
            data.put("timed_tasks", timed == null ? new ArrayList<>() : Arrays.asList(timed));
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("get_analysis_status error: " + e.getMessage());
        }
    }

    private String getAnalysisLog() {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
            MessageLog log = mgr.getMessageLog();
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("has_messages", log != null && log.hasMessages());
            data.put("status", log != null ? log.getStatus() : null);
            data.put("text", log != null ? log.toString() : "");
            data.put("task_times", mgr.getTaskTimesString());
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("get_analysis_log error: " + e.getMessage());
        }
    }

    private AddressSet collectMemoryScope(Program program, boolean execOnly, boolean initializedOnly) {
        AddressSet set = new AddressSet();
        for (MemoryBlock b : program.getMemory().getBlocks()) {
            if (execOnly && !b.isExecute()) continue;
            if (initializedOnly && !b.isInitialized()) continue;
            set.addRange(b.getStart(), b.getEnd());
        }
        return set;
    }

    private String listUndefinedRanges(Map<String, String> params, boolean execOnly) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            AddressSet scope = collectMemoryScope(program, execOnly, true);
            Address start = optionalAddress(program, params.get("start"));
            Address end = optionalAddress(program, params.get("end"));
            if (start != null && end != null) {
                AddressSet intersect = new AddressSet();
                intersect.addRange(start, end);
                scope = scope.intersect(intersect);
            }
            int minLen = parseIntOrDefault(params.get("min_length"), 1);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 1000);
            AddressSetView undef = program.getListing()
                .getUndefinedRanges(scope, true, new ConsoleTaskMonitor());
            List<Object> items = new ArrayList<>();
            long totalBytes = 0;
            AddressRangeIterator it = undef.getAddressRanges();
            while (it.hasNext()) {
                AddressRange r = it.next();
                long len = r.getLength();
                if (len < minLen) continue;
                totalBytes += len;
                Map<String, Object> e = new LinkedHashMap<>();
                e.put("start", r.getMinAddress().toString());
                e.put("end", r.getMaxAddress().toString());
                e.put("length", len);
                MemoryBlock blk = program.getMemory().getBlock(r.getMinAddress());
                e.put("block", blk != null ? blk.getName() : null);
                e.put("executable", blk != null && blk.isExecute());
                items.add(e);
            }
            Map<String, Object> data = paginatedData(offset, limit, items);
            data.put("total_bytes", totalBytes);
            data.put("executable_only", execOnly);
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("list_undefined_ranges error: " + e.getMessage());
        }
    }

    private String findPossibleFunctions(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            int maxScan = parseIntOrDefault(params.get("max_scan"), 50000);
            int alignment = parseIntOrDefault(params.get("alignment"), 0);
            if (alignment <= 0) {
                alignment = Math.max(1, program.getLanguage().getInstructionAlignment());
            }
            AddressSet exec = collectMemoryScope(program, true, true);
            Address scopeStart = optionalAddress(program, params.get("start"));
            Address scopeEnd = optionalAddress(program, params.get("end"));
            if (scopeStart != null && scopeEnd != null) {
                AddressSet s = new AddressSet();
                s.addRange(scopeStart, scopeEnd);
                exec = exec.intersect(s);
            }
            AddressSetView undef = program.getListing()
                .getUndefinedRanges(exec, true, new ConsoleTaskMonitor());
            PseudoDisassembler pd = new PseudoDisassembler(program);
            pd.setRespectExecuteFlag(true);
            List<Object> hits = new ArrayList<>();
            int scanned = 0;
            boolean truncated = false;
            AddressRangeIterator it = undef.getAddressRanges();
            outer:
            while (it.hasNext()) {
                AddressRange r = it.next();
                Address cur = r.getMinAddress();
                Address rEnd = r.getMaxAddress();
                long align = alignment;
                long rem = cur.getOffset() % align;
                if (rem != 0) {
                    try { cur = cur.add(align - rem); } catch (Exception ex) { continue; }
                }
                while (cur != null && cur.compareTo(rEnd) <= 0) {
                    if (scanned >= maxScan) { truncated = true; break outer; }
                    scanned++;
                    try {
                        if (pd.isValidSubroutine(cur, true, true)) {
                            Map<String, Object> e = new LinkedHashMap<>();
                            e.put("address", cur.toString());
                            MemoryBlock blk = program.getMemory().getBlock(cur);
                            e.put("block", blk != null ? blk.getName() : null);
                            hits.add(e);
                        }
                    } catch (Throwable t) {
                        // skip
                    }
                    try { cur = cur.add(align); } catch (Exception ex) { break; }
                }
            }
            Map<String, Object> data = paginatedData(offset, limit, hits);
            data.put("scanned_starts", scanned);
            data.put("truncated", truncated);
            data.put("alignment", alignment);
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("find_possible_functions error: " + e.getMessage());
        }
    }

    private long parseLongOrDefault(String val, long defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Long.decode(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    // ----------------------------------------------------------------------------------
    // Phase 9: Discovery helpers — pointer/jump tables and string scanning
    // ----------------------------------------------------------------------------------

    private boolean addressIsInLoadedMemory(Program program, Address addr) {
        if (addr == null) return false;
        MemoryBlock b = program.getMemory().getBlock(addr);
        return b != null && b.isInitialized();
    }

    private Address readPointer(Program program, Address at, int size) {
        try {
            byte[] buf = new byte[size];
            int n = program.getMemory().getBytes(at, buf);
            if (n != size) return null;
            boolean bigEndian = program.getLanguage().isBigEndian();
            long value = 0;
            if (bigEndian) {
                for (int i = 0; i < size; i++) value = (value << 8) | (buf[i] & 0xff);
            } else {
                for (int i = size - 1; i >= 0; i--) value = (value << 8) | (buf[i] & 0xff);
            }
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
        } catch (Exception e) {
            return null;
        }
    }

    private String findPointerTables(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            int ptrSize = program.getDefaultPointerSize();
            int minEntries = parseIntOrDefault(params.get("min_entries"), 4);
            int alignment = parseIntOrDefault(params.get("alignment"), ptrSize);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            int maxScan = parseIntOrDefault(params.get("max_scan"), 200000);
            boolean executableTargets = "1".equals(params.get("executable_targets"))
                || "true".equalsIgnoreCase(params.get("executable_targets"));

            AddressSet scope = collectMemoryScope(program, false, true);
            Address scopeStart = optionalAddress(program, params.get("start"));
            Address scopeEnd = optionalAddress(program, params.get("end"));
            if (scopeStart != null && scopeEnd != null) {
                AddressSet s = new AddressSet();
                s.addRange(scopeStart, scopeEnd);
                scope = scope.intersect(s);
            }
            AddressSetView undef = program.getListing()
                .getUndefinedRanges(scope, true, new ConsoleTaskMonitor());
            List<Object> tables = new ArrayList<>();
            int scanned = 0;
            boolean truncated = false;
            outer:
            for (AddressRange r : undef) {
                Address cur = r.getMinAddress();
                long rem = cur.getOffset() % alignment;
                if (rem != 0) {
                    try { cur = cur.add(alignment - rem); } catch (Exception ex) { continue; }
                }
                Address rEnd = r.getMaxAddress();
                while (cur != null && cur.compareTo(rEnd) <= 0) {
                    if (scanned >= maxScan) { truncated = true; break outer; }
                    scanned++;
                    Address tableStart = cur;
                    List<String> targets = new ArrayList<>();
                    Address probe = cur;
                    while (probe != null && probe.compareTo(rEnd) <= 0) {
                        if (probe.getOffset() + ptrSize - 1 > rEnd.getOffset()) break;
                        Address target = readPointer(program, probe, ptrSize);
                        if (target == null || !addressIsInLoadedMemory(program, target)) break;
                        if (executableTargets) {
                            MemoryBlock tb = program.getMemory().getBlock(target);
                            if (tb == null || !tb.isExecute()) break;
                        }
                        targets.add(target.toString());
                        try { probe = probe.add(ptrSize); } catch (Exception ex) { break; }
                    }
                    if (targets.size() >= minEntries) {
                        Map<String, Object> t = new LinkedHashMap<>();
                        t.put("start", tableStart.toString());
                        t.put("entry_size", ptrSize);
                        t.put("entry_count", targets.size());
                        t.put("byte_length", targets.size() * ptrSize);
                        t.put("targets", targets);
                        MemoryBlock blk = program.getMemory().getBlock(tableStart);
                        t.put("block", blk != null ? blk.getName() : null);
                        tables.add(t);
                        try { cur = probe; } catch (Exception ex) { break; }
                        continue;
                    }
                    try { cur = cur.add(alignment); } catch (Exception ex) { break; }
                }
            }
            Map<String, Object> data = paginatedData(offset, limit, tables);
            data.put("scanned", scanned);
            data.put("truncated", truncated);
            data.put("pointer_size", ptrSize);
            data.put("alignment", alignment);
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("find_pointer_tables error: " + e.getMessage());
        }
    }

    private String findJumpTables(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            int minEntries = parseIntOrDefault(params.get("min_entries"), 3);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            Function scopeFunc = getFunctionByAddressOrName(program,
                params.get("function_address"), params.get("function_name"));
            Listing listing = program.getListing();
            ReferenceManager refMgr = program.getReferenceManager();
            int ptrSize = program.getDefaultPointerSize();

            List<Object> tables = new ArrayList<>();
            InstructionIterator it;
            if (scopeFunc != null) {
                it = listing.getInstructions(scopeFunc.getBody(), true);
            } else {
                Address scopeStart = optionalAddress(program, params.get("start"));
                Address scopeEnd = optionalAddress(program, params.get("end"));
                if (scopeStart != null && scopeEnd != null) {
                    it = listing.getInstructions(new AddressSet(scopeStart, scopeEnd), true);
                } else {
                    it = listing.getInstructions(true);
                }
            }
            Set<String> seenInstr = new HashSet<>();
            while (it.hasNext()) {
                Instruction instr = it.next();
                FlowType ft = instr.getFlowType();
                if (ft == null) continue;
                if (!(ft.isJump() && (ft.isComputed() || instr.getReferenceIteratorTo() != null
                        || refMgr.getReferenceCountFrom(instr.getAddress()) > 1))) {
                    if (!ft.isJump() || !ft.isComputed()) continue;
                }
                if (!seenInstr.add(instr.getAddress().toString())) continue;

                List<String> dests = new ArrayList<>();
                Address tableAddr = null;
                for (Reference ref : refMgr.getReferencesFrom(instr.getAddress())) {
                    RefType rt = ref.getReferenceType();
                    if (rt == null) continue;
                    if (rt.isFlow() && rt.isJump()) {
                        dests.add(ref.getToAddress().toString());
                    } else if (rt.isData() || rt.isRead()) {
                        if (tableAddr == null) tableAddr = ref.getToAddress();
                    }
                }
                if (dests.size() < minEntries) continue;

                Map<String, Object> t = new LinkedHashMap<>();
                t.put("source", instr.getAddress().toString());
                t.put("mnemonic", instr.getMnemonicString());
                Function f = listing.getFunctionContaining(instr.getAddress());
                t.put("function", f != null ? f.getName() : null);
                t.put("function_entry", f != null ? f.getEntryPoint().toString() : null);
                t.put("table_address", tableAddr != null ? tableAddr.toString() : null);
                t.put("entry_count", dests.size());
                t.put("entry_size_hint", ptrSize);
                t.put("destinations", dests);
                tables.add(t);
            }
            Map<String, Object> data = paginatedData(offset, limit, tables);
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("find_jump_tables error: " + e.getMessage());
        }
    }

    private boolean isPrintableAscii(int b) {
        return (b >= 0x20 && b <= 0x7e) || b == 0x09 || b == 0x0a || b == 0x0d;
    }

    private String findAsciiStrings(Map<String, String> params, boolean utf16) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            int minLength = parseIntOrDefault(params.get("min_length"), utf16 ? 6 : 4);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 500);
            int maxScan = parseIntOrDefault(params.get("max_scan"), 5_000_000);
            boolean undefinedOnly = !"0".equals(params.get("undefined_only"))
                && !"false".equalsIgnoreCase(params.get("undefined_only"));
            boolean bigEndian = utf16 && program.getLanguage().isBigEndian();

            AddressSet scope = collectMemoryScope(program, false, true);
            Address scopeStart = optionalAddress(program, params.get("start"));
            Address scopeEnd = optionalAddress(program, params.get("end"));
            if (scopeStart != null && scopeEnd != null) {
                AddressSet s = new AddressSet();
                s.addRange(scopeStart, scopeEnd);
                scope = scope.intersect(s);
            }
            AddressSetView searchSpace;
            if (undefinedOnly) {
                searchSpace = program.getListing()
                    .getUndefinedRanges(scope, true, new ConsoleTaskMonitor());
            } else {
                searchSpace = scope;
            }

            Memory mem = program.getMemory();
            List<Object> hits = new ArrayList<>();
            long scanned = 0;
            boolean truncated = false;
            int step = utf16 ? 2 : 1;
            outer:
            for (AddressRange r : searchSpace) {
                Address cur = r.getMinAddress();
                Address rEnd = r.getMaxAddress();
                while (cur != null && cur.compareTo(rEnd) <= 0) {
                    if (scanned >= maxScan) { truncated = true; break outer; }
                    StringBuilder sb = new StringBuilder();
                    Address start = cur;
                    int chars = 0;
                    Address probe = cur;
                    while (probe != null && probe.compareTo(rEnd) <= 0) {
                        scanned += step;
                        if (scanned >= maxScan) { truncated = true; break; }
                        int ch;
                        try {
                            if (utf16) {
                                if (probe.getOffset() + 1 > rEnd.getOffset()) break;
                                int lo = mem.getByte(probe) & 0xff;
                                int hi = mem.getByte(probe.add(1)) & 0xff;
                                ch = bigEndian ? ((lo << 8) | hi) : ((hi << 8) | lo);
                            } else {
                                ch = mem.getByte(probe) & 0xff;
                            }
                        } catch (Exception ex) {
                            break;
                        }
                        if (ch == 0) break;
                        if (utf16) {
                            if (ch > 0x7e || !(isPrintableAscii(ch & 0xff) && ch < 0x100)) break;
                        } else {
                            if (!isPrintableAscii(ch)) break;
                        }
                        sb.append((char) ch);
                        chars++;
                        try { probe = probe.add(step); } catch (Exception ex) { break; }
                    }
                    if (chars >= minLength) {
                        Map<String, Object> h = new LinkedHashMap<>();
                        h.put("address", start.toString());
                        h.put("length", chars);
                        h.put("encoding", utf16 ? "utf16" : "ascii");
                        h.put("byte_length", chars * step + step);
                        String preview = sb.length() > 256 ? sb.substring(0, 256) : sb.toString();
                        h.put("text", escapeNonAscii(preview));
                        MemoryBlock blk = mem.getBlock(start);
                        h.put("block", blk != null ? blk.getName() : null);
                        hits.add(h);
                        try { cur = probe.add(step); } catch (Exception ex) { break; }
                        continue;
                    }
                    try { cur = cur.add(step); } catch (Exception ex) { break; }
                }
            }
            Map<String, Object> data = paginatedData(offset, limit, hits);
            data.put("scanned_bytes", scanned);
            data.put("truncated", truncated);
            data.put("min_length", minLength);
            data.put("undefined_only", undefinedOnly);
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError((utf16 ? "find_utf16_strings" : "find_ascii_strings")
                + " error: " + e.getMessage());
        }
    }

    // ----------------------------------------------------------------------------------
    // Phase 10: Program lifecycle
    // ----------------------------------------------------------------------------------

    private String listOpenPrograms() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return jsonError("ProgramManager service not available");
        try {
            Program current = pm.getCurrentProgram();
            List<Object> items = new ArrayList<>();
            for (Program p : pm.getAllOpenPrograms()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("name", p.getName());
                DomainFile df = p.getDomainFile();
                m.put("path", df != null ? df.getPathname() : null);
                m.put("language", p.getLanguage().getLanguageID().toString());
                m.put("compiler_spec", p.getCompilerSpec().getCompilerSpecID().toString());
                m.put("image_base", p.getImageBase().toString());
                m.put("function_count", p.getFunctionManager().getFunctionCount());
                m.put("changed", df != null && df.isChanged());
                m.put("read_only", df != null && df.isReadOnly());
                m.put("current", p == current);
                items.add(m);
            }
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("count", items.size());
            data.put("items", items);
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("list_open_programs error: " + e.getMessage());
        }
    }

    private Program findOpenProgram(String name, String path) {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return null;
        for (Program p : pm.getAllOpenPrograms()) {
            DomainFile df = p.getDomainFile();
            if (path != null && !path.isEmpty() && df != null && path.equals(df.getPathname())) return p;
            if (name != null && !name.isEmpty() && name.equals(p.getName())) return p;
        }
        return null;
    }

    private String selectProgram(Map<String, String> params) {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return jsonError("ProgramManager service not available");
        try {
            Program target = findOpenProgram(params.get("name"), params.get("path"));
            if (target == null) return jsonError("program not found among open programs");
            final Program f = target;
            SwingUtilities.invokeAndWait(() -> pm.setCurrentProgram(f));
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("name", target.getName());
            r.put("path", target.getDomainFile() != null ? target.getDomainFile().getPathname() : null);
            return jsonOk(r);
        } catch (Exception e) {
            return jsonError("select_program error: " + e.getMessage());
        }
    }

    private String saveProgram(Map<String, String> params) {
        try {
            Program target = findOpenProgram(params.get("name"), params.get("path"));
            if (target == null) target = getCurrentProgram();
            if (target == null) return jsonError("no program to save");
            final Program p = target;
            DomainFile df = p.getDomainFile();
            if (df == null) return jsonError("program has no domain file");
            AtomicBoolean ok = new AtomicBoolean(false);
            StringBuilder err = new StringBuilder();
            SwingUtilities.invokeAndWait(() -> {
                try {
                    df.save(new ConsoleTaskMonitor());
                    ok.set(true);
                } catch (Exception ex) {
                    err.append(ex.getMessage());
                }
            });
            if (!ok.get()) return jsonError("save failed: " + err);
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("name", p.getName());
            r.put("path", df.getPathname());
            r.put("changed", df.isChanged());
            return jsonOk(r);
        } catch (Exception e) {
            return jsonError("save_program error: " + e.getMessage());
        }
    }

    private String closeProgram(Map<String, String> params) {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return jsonError("ProgramManager service not available");
        try {
            Program target = findOpenProgram(params.get("name"), params.get("path"));
            if (target == null) target = pm.getCurrentProgram();
            if (target == null) return jsonError("no program to close");
            boolean ignoreChanges = "1".equals(params.get("ignore_changes"))
                || "true".equalsIgnoreCase(params.get("ignore_changes"));
            final Program p = target;
            AtomicBoolean ok = new AtomicBoolean(false);
            SwingUtilities.invokeAndWait(() -> {
                boolean result = ignoreChanges ? pm.closeProgram(p, true) : pm.closeProgram(p, false);
                ok.set(result);
            });
            if (!ok.get()) return jsonError("close refused (possibly unsaved changes; set ignore_changes=true)");
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("name", p.getName());
            return jsonOk(r);
        } catch (Exception e) {
            return jsonError("close_program error: " + e.getMessage());
        }
    }

    private String importFile(Map<String, String> params) {
        try {
            String path = required(params.get("path"), "path");
            File file = new File(path);
            if (!file.exists() || !file.isFile()) return jsonError("file not found: " + path);
            Project project = tool.getProject();
            if (project == null) return jsonError("no active project");
            String folderPath = params.get("folder");
            String projectFolderPath = (folderPath == null || folderPath.isEmpty()) ? "/" : folderPath;
            if (!projectFolderPath.startsWith("/")) projectFolderPath = "/" + projectFolderPath;
            String loaderName = trimOrNull(params.get("loader_name"));
            String languageIdStr = trimOrNull(params.get("language_id"));
            String compilerSpecStr = trimOrNull(params.get("compiler_spec"));
            String imageBaseStr = trimOrNull(params.get("image_base"));
            String loaderOptionsRaw = trimOrNull(params.get("loader_options"));
            final String pfPath = projectFolderPath;
            final boolean openProgram = !"0".equals(params.get("open")) && !"false".equalsIgnoreCase(params.get("open"));
            final ProgramManager pm = tool.getService(ProgramManager.class);

            Class<? extends Loader> loaderClass = null;
            if (loaderName != null) {
                loaderClass = resolveLoaderClass(loaderName);
                if (loaderClass == null) return jsonError("unknown loader: " + loaderName);
            }
            Language language = null;
            CompilerSpec compilerSpec = null;
            if (languageIdStr != null) {
                LanguageService ls = DefaultLanguageService.getLanguageService();
                try {
                    language = ls.getLanguage(new LanguageID(languageIdStr));
                } catch (Exception ex) {
                    return jsonError("unknown language_id: " + languageIdStr);
                }
                if (compilerSpecStr != null) {
                    try {
                        compilerSpec = language.getCompilerSpecByID(new CompilerSpecID(compilerSpecStr));
                    } catch (Exception ex) {
                        return jsonError("unknown compiler_spec '" + compilerSpecStr + "' for " + languageIdStr);
                    }
                } else {
                    compilerSpec = language.getDefaultCompilerSpec();
                }
            }
            final List<Pair<String, String>> loaderOpts = parseLoaderOptions(loaderOptionsRaw);
            final Language fLang = language;
            final CompilerSpec fCspec = compilerSpec;
            final Class<? extends Loader> fLoaderClass = loaderClass;

            AtomicBoolean ok = new AtomicBoolean(false);
            final StringBuilder err = new StringBuilder();
            final Map<String, Object> result = new LinkedHashMap<>();
            SwingUtilities.invokeAndWait(() -> {
                LoadResults<Program> lr = null;
                try {
                    MessageLog log = new MessageLog();
                    TaskMonitor monitor = new ConsoleTaskMonitor();
                    if (fLoaderClass != null && fLang != null) {
                        lr = AutoImporter.importByUsingSpecificLoaderClassAndLcs(
                            file, project, pfPath, fLoaderClass, loaderOpts,
                            fLang, fCspec, this, log, monitor);
                    } else if (fLoaderClass != null) {
                        lr = AutoImporter.importByUsingSpecificLoaderClass(
                            file, project, pfPath, fLoaderClass, loaderOpts,
                            this, log, monitor);
                    } else if (fLang != null) {
                        lr = AutoImporter.importByLookingForLcs(
                            file, project, pfPath, fLang, fCspec,
                            this, log, monitor);
                    } else {
                        lr = AutoImporter.importByUsingBestGuess(
                            file, project, pfPath, this, log, monitor);
                    }
                    if (lr == null || lr.size() == 0) {
                        err.append("loader produced no programs");
                        String msg = log.toString();
                        if (msg != null && !msg.isEmpty()) err.append(": ").append(msg);
                        return;
                    }
                    Program p = lr.getPrimaryDomainObject(this);
                    try {
                        if (imageBaseStr != null) {
                            int tx = p.startTransaction("import_set_image_base");
                            boolean done = false;
                            try {
                                Address base = p.getAddressFactory().getAddress(imageBaseStr);
                                p.setImageBase(base, true);
                                done = true;
                            } finally {
                                p.endTransaction(tx, done);
                            }
                        }
                        result.put("name", p.getName());
                        DomainFile df = p.getDomainFile();
                        result.put("path", df != null ? df.getPathname() : null);
                        result.put("language", p.getLanguage().getLanguageID().toString());
                        result.put("compiler_spec", p.getCompilerSpec().getCompilerSpecID().toString());
                        result.put("image_base", p.getImageBase().toString());
                        if (pm != null && openProgram) {
                            pm.openProgram(p);
                        }
                        ok.set(true);
                    } finally {
                        // release our consumer hold on the program; ProgramManager keeps its own hold if we opened it.
                        try { p.release(this); } catch (Exception ignored) {}
                    }
                } catch (Throwable t) {
                    err.append(t.getMessage() == null ? t.toString() : t.getMessage());
                } finally {
                    if (lr != null) {
                        try { lr.release(this); } catch (Exception ignored) {}
                    }
                }
            });
            if (!ok.get()) return jsonError("import_file failed: " + err);
            return jsonOk(result);
        } catch (Exception e) {
            return jsonError("import_file error: " + e.getMessage());
        }
    }

    private String trimOrNull(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private List<Pair<String, String>> parseLoaderOptions(String raw) {
        List<Pair<String, String>> opts = new ArrayList<>();
        if (raw == null || raw.isEmpty()) return opts;
        // Accept JSON-ish object {"k":"v",...} or k=v[,k=v]* shorthand.
        String s = raw.trim();
        if (s.startsWith("{") && s.endsWith("}")) {
            String body = s.substring(1, s.length() - 1).trim();
            if (body.isEmpty()) return opts;
            // Very small parser: split on commas not inside quotes, then key:value
            List<String> parts = splitTopLevel(body, ',');
            for (String part : parts) {
                int colon = findUnquoted(part, ':');
                if (colon < 0) continue;
                String k = stripJsonString(part.substring(0, colon).trim());
                String v = stripJsonString(part.substring(colon + 1).trim());
                if (k != null) opts.add(new Pair<>(k, v == null ? "" : v));
            }
        } else {
            for (String pair : s.split(",")) {
                int eq = pair.indexOf('=');
                if (eq < 0) continue;
                String k = pair.substring(0, eq).trim();
                String v = pair.substring(eq + 1).trim();
                if (!k.isEmpty()) opts.add(new Pair<>(k, v));
            }
        }
        return opts;
    }

    private List<String> splitTopLevel(String s, char delim) {
        List<String> out = new ArrayList<>();
        int depth = 0;
        boolean inStr = false;
        boolean esc = false;
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (esc) { cur.append(c); esc = false; continue; }
            if (inStr) {
                if (c == '\\') { esc = true; cur.append(c); continue; }
                if (c == '"') inStr = false;
                cur.append(c);
                continue;
            }
            if (c == '"') { inStr = true; cur.append(c); continue; }
            if (c == '{' || c == '[') depth++;
            else if (c == '}' || c == ']') depth--;
            if (depth == 0 && c == delim) { out.add(cur.toString()); cur.setLength(0); continue; }
            cur.append(c);
        }
        if (cur.length() > 0) out.add(cur.toString());
        return out;
    }

    private int findUnquoted(String s, char target) {
        boolean inStr = false;
        boolean esc = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (esc) { esc = false; continue; }
            if (inStr) {
                if (c == '\\') { esc = true; continue; }
                if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') { inStr = true; continue; }
            if (c == target) return i;
        }
        return -1;
    }

    private String stripJsonString(String s) {
        if (s == null) return null;
        s = s.trim();
        if (s.isEmpty()) return null;
        if (s.startsWith("\"") && s.endsWith("\"") && s.length() >= 2) {
            return s.substring(1, s.length() - 1)
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
        }
        if (s.equals("null")) return null;
        return s;
    }

    private String openProgram(Map<String, String> params) {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return jsonError("ProgramManager service not available");
        try {
            String path = required(params.get("path"), "path");
            Project project = tool.getProject();
            if (project == null) return jsonError("no active project");
            DomainFile df = project.getProjectData().getFile(path);
            if (df == null) return jsonError("project file not found: " + path);
            final DomainFile f = df;
            AtomicBoolean ok = new AtomicBoolean(false);
            final StringBuilder err = new StringBuilder();
            final Map<String, Object> result = new LinkedHashMap<>();
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Program p = (Program) f.getDomainObject(this, false, false, new ConsoleTaskMonitor());
                    pm.openProgram(p);
                    result.put("name", p.getName());
                    result.put("path", f.getPathname());
                    result.put("language", p.getLanguage().getLanguageID().toString());
                    p.release(this);
                    ok.set(true);
                } catch (Exception ex) {
                    err.append(ex.getMessage());
                }
            });
            if (!ok.get()) return jsonError("open_program failed: " + err);
            return jsonOk(result);
        } catch (Exception e) {
            return jsonError("open_program error: " + e.getMessage());
        }
    }

    // ----------------------------------------------------------------------------------
    // Phase 11: Exports
    // ----------------------------------------------------------------------------------

    private String writeFile(String path, byte[] data) throws IOException {
        File f = new File(path);
        File parent = f.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IOException("cannot create parent directory: " + parent);
        }
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write(data);
        }
        return f.getAbsolutePath();
    }

    private String writeTextFile(String path, String text) throws IOException {
        return writeFile(path, text.getBytes(StandardCharsets.UTF_8));
    }

    private String exportBytes(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            Address start = parseAddress(program, required(params.get("start"), "start"));
            String endStr = params.get("end");
            String lengthStr = params.get("length");
            long length;
            if (endStr != null && !endStr.isEmpty()) {
                Address end = parseAddress(program, endStr);
                length = end.subtract(start) + 1;
            } else {
                length = parseLongOrDefault(lengthStr, -1);
            }
            if (length <= 0) return jsonError("end or length required");
            if (length > 50_000_000) return jsonError("range too large (>50MB)");
            byte[] buf = new byte[(int) length];
            int n = program.getMemory().getBytes(start, buf);
            byte[] data = n == buf.length ? buf : Arrays.copyOf(buf, n);
            String filePath = params.get("path");
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("start", start.toString());
            r.put("length", n);
            if (filePath != null && !filePath.isEmpty()) {
                r.put("path", writeFile(filePath, data));
                r.put("hex", null);
            } else {
                StringBuilder sb = new StringBuilder(n * 2);
                for (int i = 0; i < n; i++) sb.append(String.format("%02x", data[i] & 0xff));
                r.put("hex", sb.toString());
            }
            return jsonOk(r);
        } catch (Exception e) {
            return jsonError("export_bytes error: " + e.getMessage());
        }
    }

    private String exportPatchedBinary(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            String filePath = required(params.get("path"), "path");
            boolean initializedOnly = !"0".equals(params.get("initialized_only"))
                && !"false".equalsIgnoreCase(params.get("initialized_only"));
            Memory mem = program.getMemory();
            try (FileOutputStream out = new FileOutputStream(filePath)) {
                long total = 0;
                Map<String, Object> blocks = new LinkedHashMap<>();
                List<Object> blockList = new ArrayList<>();
                for (MemoryBlock b : mem.getBlocks()) {
                    if (initializedOnly && !b.isInitialized()) continue;
                    long len = b.getEnd().subtract(b.getStart()) + 1;
                    byte[] buf = new byte[(int) Math.min(len, 1 << 20)];
                    Address cur = b.getStart();
                    long remaining = len;
                    while (remaining > 0) {
                        int chunk = (int) Math.min(buf.length, remaining);
                        int n = mem.getBytes(cur, buf, 0, chunk);
                        if (n <= 0) break;
                        out.write(buf, 0, n);
                        remaining -= n;
                        if (remaining > 0) cur = cur.add(n);
                    }
                    total += len - remaining;
                    Map<String, Object> bm = new LinkedHashMap<>();
                    bm.put("name", b.getName());
                    bm.put("start", b.getStart().toString());
                    bm.put("end", b.getEnd().toString());
                    bm.put("length", len);
                    blockList.add(bm);
                }
                blocks.put("blocks", blockList);
                blocks.put("path", new File(filePath).getAbsolutePath());
                blocks.put("total_bytes", total);
                blocks.put("initialized_only", initializedOnly);
                return jsonOk(blocks);
            }
        } catch (Exception e) {
            return jsonError("export_patched_binary error: " + e.getMessage());
        }
    }

    private String exportSymbols(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            String format = lower(params.get("format"));
            if (format == null || format.isEmpty()) format = "json";
            String filePath = params.get("path");
            boolean userOnly = "1".equals(params.get("user_only"))
                || "true".equalsIgnoreCase(params.get("user_only"));
            List<Map<String, Object>> rows = new ArrayList<>();
            SymbolTable st = program.getSymbolTable();
            for (Symbol s : st.getAllSymbols(true)) {
                if (userOnly && s.getSource() != SourceType.USER_DEFINED) continue;
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("address", s.getAddress().toString());
                r.put("name", s.getName());
                r.put("namespace", s.getParentNamespace() != null ? s.getParentNamespace().getName(true) : null);
                r.put("type", s.getSymbolType() != null ? s.getSymbolType().toString() : null);
                r.put("source", s.getSource() != null ? s.getSource().toString() : null);
                r.put("primary", s.isPrimary());
                rows.add(r);
            }
            String body;
            if (format.equals("csv")) {
                StringBuilder sb = new StringBuilder("address,name,namespace,type,source,primary\n");
                for (Map<String, Object> r : rows) {
                    sb.append(r.get("address")).append(',')
                      .append(csvField(String.valueOf(r.get("name")))).append(',')
                      .append(csvField(String.valueOf(r.get("namespace")))).append(',')
                      .append(r.get("type")).append(',')
                      .append(r.get("source")).append(',')
                      .append(r.get("primary")).append('\n');
                }
                body = sb.toString();
            } else if (format.equals("text") || format.equals("txt")) {
                StringBuilder sb = new StringBuilder();
                for (Map<String, Object> r : rows) {
                    sb.append(r.get("address")).append(' ').append(r.get("name")).append('\n');
                }
                body = sb.toString();
            } else {
                body = toJson(rows);
            }
            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("count", rows.size());
            resp.put("format", format);
            if (filePath != null && !filePath.isEmpty()) {
                resp.put("path", writeTextFile(filePath, body));
            } else {
                resp.put("body", body);
            }
            return jsonOk(resp);
        } catch (Exception e) {
            return jsonError("export_symbols error: " + e.getMessage());
        }
    }

    private String csvField(String s) {
        if (s == null) return "";
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }

    private String exportFunctionMap(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            String format = lower(params.get("format"));
            if (format == null || format.isEmpty()) format = "json";
            String filePath = params.get("path");
            List<Map<String, Object>> rows = new ArrayList<>();
            for (Function f : program.getFunctionManager().getFunctions(true)) {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("entry", f.getEntryPoint().toString());
                r.put("name", f.getName());
                r.put("namespace", f.getParentNamespace() != null ? f.getParentNamespace().getName(true) : null);
                r.put("body_size", f.getBody() != null ? f.getBody().getNumAddresses() : 0);
                r.put("signature", f.getSignature() != null ? f.getSignature().toString() : null);
                r.put("calling_convention", f.getCallingConventionName());
                r.put("source", f.getSymbol() != null ? f.getSymbol().getSource().toString() : null);
                r.put("thunk", f.isThunk());
                r.put("external", f.isExternal());
                rows.add(r);
            }
            String body;
            if (format.equals("csv")) {
                StringBuilder sb = new StringBuilder("entry,name,namespace,body_size,signature\n");
                for (Map<String, Object> r : rows) {
                    sb.append(r.get("entry")).append(',')
                      .append(csvField(String.valueOf(r.get("name")))).append(',')
                      .append(csvField(String.valueOf(r.get("namespace")))).append(',')
                      .append(r.get("body_size")).append(',')
                      .append(csvField(String.valueOf(r.get("signature")))).append('\n');
                }
                body = sb.toString();
            } else if (format.equals("text") || format.equals("txt")) {
                StringBuilder sb = new StringBuilder();
                for (Map<String, Object> r : rows) {
                    sb.append(r.get("entry")).append(' ').append(r.get("name")).append('\n');
                }
                body = sb.toString();
            } else {
                body = toJson(rows);
            }
            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("count", rows.size());
            resp.put("format", format);
            if (filePath != null && !filePath.isEmpty()) {
                resp.put("path", writeTextFile(filePath, body));
            } else {
                resp.put("body", body);
            }
            return jsonOk(resp);
        } catch (Exception e) {
            return jsonError("export_function_map error: " + e.getMessage());
        }
    }

    private String exportCHeader(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            String filePath = params.get("path");
            String categoryFilter = params.get("category");
            DataTypeManager dtm = program.getDataTypeManager();
            StringBuilder sb = new StringBuilder();
            sb.append("// Auto-generated C header from GhidraMCP\n");
            sb.append("// Program: ").append(program.getName()).append("\n\n");
            int count = 0;
            Iterator<DataType> it = dtm.getAllDataTypes();
            while (it.hasNext()) {
                DataType dt = it.next();
                if (categoryFilter != null && !categoryFilter.isEmpty()) {
                    if (!dt.getCategoryPath().getPath().contains(categoryFilter)) continue;
                }
                if (dt instanceof Structure || dt instanceof Union || dt instanceof EnumDataType
                    || dt instanceof TypeDef) {
                    String repr;
                    try {
                        repr = dt.toString();
                    } catch (Exception ex) {
                        continue;
                    }
                    sb.append("// path=").append(dt.getPathName()).append("\n");
                    sb.append("// ").append(dt.getClass().getSimpleName()).append(" ").append(dt.getName())
                      .append(" size=").append(dt.getLength()).append("\n");
                    sb.append(repr).append("\n\n");
                    count++;
                }
            }
            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("types_exported", count);
            if (filePath != null && !filePath.isEmpty()) {
                resp.put("path", writeTextFile(filePath, sb.toString()));
            } else {
                resp.put("body", sb.toString());
            }
            return jsonOk(resp);
        } catch (Exception e) {
            return jsonError("export_c_header error: " + e.getMessage());
        }
    }

    private String exportAnalysisReport(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            String format = lower(params.get("format"));
            if (format == null || format.isEmpty()) format = "json";
            String filePath = params.get("path");
            Map<String, Object> report = new LinkedHashMap<>();
            report.put("name", program.getName());
            report.put("language", program.getLanguage().getLanguageID().toString());
            report.put("compiler", program.getCompilerSpec().getCompilerSpecID().toString());
            report.put("image_base", program.getImageBase().toString());
            report.put("min_address", program.getMinAddress().toString());
            report.put("max_address", program.getMaxAddress().toString());
            report.put("function_count", program.getFunctionManager().getFunctionCount());

            int userRenamedFns = 0;
            int defaultFns = 0;
            for (Function f : program.getFunctionManager().getFunctions(true)) {
                SourceType src = f.getSymbol() != null ? f.getSymbol().getSource() : SourceType.DEFAULT;
                if (src == SourceType.USER_DEFINED || src == SourceType.IMPORTED) userRenamedFns++;
                else defaultFns++;
            }
            report.put("user_named_functions", userRenamedFns);
            report.put("default_named_functions", defaultFns);

            int userSymbols = 0;
            for (Symbol s : program.getSymbolTable().getAllSymbols(false)) {
                if (s.getSource() == SourceType.USER_DEFINED) userSymbols++;
            }
            report.put("user_defined_symbols", userSymbols);

            int comments = 0;
            for (int type : new int[]{CodeUnit.PLATE_COMMENT, CodeUnit.PRE_COMMENT,
                CodeUnit.POST_COMMENT, CodeUnit.EOL_COMMENT, CodeUnit.REPEATABLE_COMMENT}) {
                AddressIterator ci = program.getListing().getCommentAddressIterator(type,
                    program.getMemory(), true);
                while (ci.hasNext()) { ci.next(); comments++; }
            }
            report.put("comment_count", comments);

            int structs = 0, unions = 0, enums = 0, typedefs = 0;
            Iterator<DataType> dts = program.getDataTypeManager().getAllDataTypes();
            while (dts.hasNext()) {
                DataType dt = dts.next();
                if (dt instanceof Structure) structs++;
                else if (dt instanceof Union) unions++;
                else if (dt instanceof EnumDataType) enums++;
                else if (dt instanceof TypeDef) typedefs++;
            }
            Map<String, Object> typeCounts = new LinkedHashMap<>();
            typeCounts.put("struct", structs);
            typeCounts.put("union", unions);
            typeCounts.put("enum", enums);
            typeCounts.put("typedef", typedefs);
            report.put("type_counts", typeCounts);

            report.put("patch_count", patchHistory.size());

            AddressSet exec = collectMemoryScope(program, true, true);
            AddressSetView undef = program.getListing()
                .getUndefinedRanges(exec, true, new ConsoleTaskMonitor());
            long undefBytes = 0;
            for (AddressRange r : undef) undefBytes += r.getLength();
            report.put("undefined_exec_bytes", undefBytes);

            String body;
            if (format.equals("text") || format.equals("txt")) {
                StringBuilder sb = new StringBuilder();
                sb.append("# GhidraMCP Analysis Report\n");
                for (Map.Entry<String, Object> e : report.entrySet()) {
                    sb.append(e.getKey()).append(": ").append(e.getValue()).append('\n');
                }
                body = sb.toString();
            } else {
                body = toJson(report);
            }
            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("format", format);
            if (filePath != null && !filePath.isEmpty()) {
                resp.put("path", writeTextFile(filePath, body));
            } else {
                resp.put("body", body);
            }
            return jsonOk(resp);
        } catch (Exception e) {
            return jsonError("export_analysis_report error: " + e.getMessage());
        }
    }

    // ----------------------------------------------------------------------------------
    // Phase 12: Patch helpers
    // ----------------------------------------------------------------------------------

    private static class PatchRecord {
        final int id;
        final String address;
        final byte[] originalBytes;
        final byte[] newBytes;
        final String rationale;
        final String timestamp;
        boolean reverted;
        PatchRecord(int id, String address, byte[] orig, byte[] nu, String rationale) {
            this.id = id;
            this.address = address;
            this.originalBytes = orig;
            this.newBytes = nu;
            this.rationale = rationale;
            this.timestamp = Instant.now().toString();
            this.reverted = false;
        }
        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("address", address);
            m.put("original_bytes", hexEncode(originalBytes));
            m.put("new_bytes", hexEncode(newBytes));
            m.put("length", newBytes != null ? newBytes.length : 0);
            m.put("rationale", rationale);
            m.put("timestamp", timestamp);
            m.put("reverted", reverted);
            return m;
        }
    }

    private static String hexEncode(byte[] data) {
        if (data == null) return null;
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    private final List<PatchRecord> patchHistory = Collections.synchronizedList(new ArrayList<>());
    private final AtomicInteger nextPatchId = new AtomicInteger(1);

    private PatchRecord recordPatch(Program program, Address address, byte[] original,
                                    byte[] replacement, String rationale) {
        PatchRecord rec = new PatchRecord(nextPatchId.getAndIncrement(),
            address.toString(), original, replacement, rationale);
        patchHistory.add(rec);
        return rec;
    }

    private byte[] readMemBytes(Program program, Address addr, int length) throws MemoryAccessException {
        byte[] buf = new byte[length];
        int n = program.getMemory().getBytes(addr, buf);
        return n == length ? buf : Arrays.copyOf(buf, n);
    }

    private String assembleInstruction(Map<String, String> params, boolean writeToMemory) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            Address addr = parseAddress(program, required(params.get("address"), "address"));
            String instructionStr = required(params.get("instruction"), "instruction");
            boolean dryRun = "1".equals(params.get("dry_run"))
                || "true".equalsIgnoreCase(params.get("dry_run"));
            Assembler assembler = Assemblers.getAssembler(program);
            byte[] bytes;
            try {
                bytes = assembler.assembleLine(addr, instructionStr);
            } catch (AssemblyException ae) {
                return jsonError("assembly failed: " + ae.getMessage());
            }
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("address", addr.toString());
            r.put("instruction", instructionStr);
            r.put("bytes", hexEncode(bytes));
            r.put("length", bytes.length);

            if (!writeToMemory || dryRun) {
                r.put("written", false);
                return jsonOk(r);
            }
            byte[] original = readMemBytes(program, addr, bytes.length);
            AtomicBoolean ok = new AtomicBoolean(false);
            StringBuilder err = new StringBuilder();
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("patch_instruction");
                try {
                    program.getMemory().setBytes(addr, bytes);
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
            if (!ok.get()) return jsonError("patch failed: " + err);
            PatchRecord rec = recordPatch(program, addr, original, bytes,
                params.getOrDefault("rationale", "patch_instruction: " + instructionStr));
            r.put("written", true);
            r.put("patch_id", rec.id);
            r.put("original_bytes", hexEncode(original));
            return jsonOk(r);
        } catch (Exception e) {
            return jsonError("assemble_instruction error: " + e.getMessage());
        }
    }

    private byte[] computeNopBytes(Program program, int length) {
        Assembler assembler = Assemblers.getAssembler(program);
        for (String mnem : new String[]{"NOP", "nop"}) {
            try {
                byte[] one = assembler.assembleLine(program.getMinAddress(), mnem);
                if (one != null && one.length > 0) {
                    if (length % one.length != 0) return null;
                    byte[] out = new byte[length];
                    for (int i = 0; i < length; i += one.length) {
                        System.arraycopy(one, 0, out, i, one.length);
                    }
                    return out;
                }
            } catch (Exception ignored) { }
        }
        // x86-ish fallback
        byte[] out = new byte[length];
        Arrays.fill(out, (byte) 0x90);
        return out;
    }

    private String nopRange(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            Address start = parseAddress(program, required(params.get("start"), "start"));
            String endStr = params.get("end");
            String lengthStr = params.get("length");
            long length;
            if (endStr != null && !endStr.isEmpty()) {
                Address end = parseAddress(program, endStr);
                length = end.subtract(start) + 1;
            } else {
                length = parseLongOrDefault(lengthStr, -1);
            }
            if (length <= 0) return jsonError("end or length required");
            if (length > 65536) return jsonError("length too large");
            byte[] nopBytes = computeNopBytes(program, (int) length);
            if (nopBytes == null) return jsonError("could not derive NOP encoding for this architecture");
            boolean dryRun = "1".equals(params.get("dry_run"))
                || "true".equalsIgnoreCase(params.get("dry_run"));
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("start", start.toString());
            r.put("length", length);
            r.put("bytes", hexEncode(nopBytes));
            if (dryRun) {
                r.put("written", false);
                return jsonOk(r);
            }
            byte[] original = readMemBytes(program, start, (int) length);
            AtomicBoolean ok = new AtomicBoolean(false);
            StringBuilder err = new StringBuilder();
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("nop_range");
                try {
                    program.getMemory().setBytes(start, nopBytes);
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
            if (!ok.get()) return jsonError("nop_range failed: " + err);
            PatchRecord rec = recordPatch(program, start, original, nopBytes,
                params.getOrDefault("rationale", "nop_range"));
            r.put("written", true);
            r.put("patch_id", rec.id);
            r.put("original_bytes", hexEncode(original));
            return jsonOk(r);
        } catch (Exception e) {
            return jsonError("nop_range error: " + e.getMessage());
        }
    }

    private String patchFlowTarget(Map<String, String> params, boolean isCall) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            Address addr = parseAddress(program, required(params.get("address"), "address"));
            Address target = parseAddress(program, required(params.get("target"), "target"));
            boolean dryRun = "1".equals(params.get("dry_run"))
                || "true".equalsIgnoreCase(params.get("dry_run"));
            Instruction instr = program.getListing().getInstructionAt(addr);
            if (instr == null) return jsonError("no instruction at " + addr);
            FlowType ft = instr.getFlowType();
            if (ft == null || (isCall ? !ft.isCall() : !ft.isJump())) {
                return jsonError("instruction at " + addr + " is not a "
                    + (isCall ? "call" : "branch"));
            }
            String mnem = instr.getMnemonicString();
            String text = mnem + " 0x" + Long.toHexString(target.getOffset());

            Assembler assembler = Assemblers.getAssembler(program);
            byte[] bytes;
            try {
                bytes = assembler.assembleLine(addr, text);
            } catch (AssemblyException ae) {
                return jsonError("re-assembly failed for '" + text + "': " + ae.getMessage());
            }
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("address", addr.toString());
            r.put("mnemonic", mnem);
            r.put("new_target", target.toString());
            r.put("new_bytes", hexEncode(bytes));
            r.put("length", bytes.length);
            r.put("original_length", instr.getLength());
            if (bytes.length > instr.getLength()) {
                return jsonError("re-assembled instruction longer than original ("
                    + bytes.length + " > " + instr.getLength() + ")");
            }
            if (dryRun) {
                r.put("written", false);
                return jsonOk(r);
            }
            byte[] original = readMemBytes(program, addr, instr.getLength());
            byte[] payload = bytes;
            if (bytes.length < instr.getLength()) {
                // pad with NOPs after the new instruction
                byte[] nop = computeNopBytes(program, instr.getLength() - bytes.length);
                if (nop != null) {
                    payload = new byte[instr.getLength()];
                    System.arraycopy(bytes, 0, payload, 0, bytes.length);
                    System.arraycopy(nop, 0, payload, bytes.length, nop.length);
                }
            }
            final byte[] toWrite = payload;
            AtomicBoolean ok = new AtomicBoolean(false);
            StringBuilder err = new StringBuilder();
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(isCall ? "patch_call_target" : "patch_branch_target");
                try {
                    program.getMemory().setBytes(addr, toWrite);
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
            if (!ok.get()) return jsonError("patch failed: " + err);
            PatchRecord rec = recordPatch(program, addr, original, toWrite,
                params.getOrDefault("rationale", (isCall ? "patch_call_target -> " : "patch_branch_target -> ")
                    + target));
            r.put("written", true);
            r.put("patch_id", rec.id);
            r.put("original_bytes", hexEncode(original));
            r.put("payload", hexEncode(toWrite));
            return jsonOk(r);
        } catch (Exception e) {
            return jsonError((isCall ? "patch_call_target" : "patch_branch_target")
                + " error: " + e.getMessage());
        }
    }

    private String createPatchRecord(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            Address addr = parseAddress(program, required(params.get("address"), "address"));
            String hex = required(params.get("new_bytes"), "new_bytes");
            byte[] newBytes = parseHexBytes(hex);
            String origHex = params.get("original_bytes");
            byte[] origBytes = (origHex != null && !origHex.isEmpty())
                ? parseHexBytes(origHex) : readMemBytes(program, addr, newBytes.length);
            PatchRecord rec = recordPatch(program, addr, origBytes, newBytes,
                params.getOrDefault("rationale", "manual record"));
            return jsonOk(rec.toMap());
        } catch (Exception e) {
            return jsonError("create_patch_record error: " + e.getMessage());
        }
    }

    private String listPatches(Map<String, String> params) {
        try {
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            boolean activeOnly = "1".equals(params.get("active_only"))
                || "true".equalsIgnoreCase(params.get("active_only"));
            List<Object> items = new ArrayList<>();
            synchronized (patchHistory) {
                for (PatchRecord rec : patchHistory) {
                    if (activeOnly && rec.reverted) continue;
                    items.add(rec.toMap());
                }
            }
            return jsonOk(paginatedData(offset, limit, items));
        } catch (Exception e) {
            return jsonError("list_patches error: " + e.getMessage());
        }
    }

    private String revertPatch(Map<String, String> params) {
        Program program = getCurrentProgram();
        if (program == null) return jsonError("No program loaded");
        try {
            String idStr = required(params.get("id"), "id");
            int id;
            try { id = Integer.parseInt(idStr); }
            catch (NumberFormatException e) { return jsonError("id must be an integer"); }
            PatchRecord target = null;
            synchronized (patchHistory) {
                for (PatchRecord rec : patchHistory) {
                    if (rec.id == id) { target = rec; break; }
                }
            }
            if (target == null) return jsonError("patch id not found: " + id);
            if (target.reverted) return jsonError("patch already reverted");
            final PatchRecord patch = target;
            Address addr = parseAddress(program, patch.address);
            AtomicBoolean ok = new AtomicBoolean(false);
            StringBuilder err = new StringBuilder();
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("revert_patch:" + patch.id);
                try {
                    program.getMemory().setBytes(addr, patch.originalBytes);
                    patch.reverted = true;
                    ok.set(true);
                } catch (Exception e) {
                    err.append(e.getMessage());
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
            if (!ok.get()) return jsonError("revert failed: " + err);
            return jsonOk(patch.toMap());
        } catch (Exception e) {
            return jsonError("revert_patch error: " + e.getMessage());
        }
    }

    // ----------------------------------------------------------------------------------
    // Phase 13: Project lifecycle, async analysis, navigation, bring-up
    // ----------------------------------------------------------------------------------

    private ProjectManager getProjectManager() {
        Project active = AppInfo.getActiveProject();
        if (active != null) return active.getProjectManager();
        FrontEndTool fe = AppInfo.getFrontEndTool();
        if (fe == null) return null;
        try {
            java.lang.reflect.Field f = FrontEndTool.class.getDeclaredField("projectManager");
            f.setAccessible(true);
            Object pm = f.get(fe);
            if (pm instanceof ProjectManager) return (ProjectManager) pm;
        } catch (Exception ignored) {}
        try {
            java.lang.reflect.Method m = fe.getClass().getMethod("getProjectManager");
            Object pm = m.invoke(fe);
            if (pm instanceof ProjectManager) return (ProjectManager) pm;
        } catch (Exception ignored) {}
        return null;
    }

    private ProjectLocator parseProjectLocator(String path) {
        File f = new File(path);
        String name = f.getName();
        if (name.endsWith(ProjectLocator.getProjectExtension())) {
            name = name.substring(0, name.length() - ProjectLocator.getProjectExtension().length());
        }
        String dir = f.getParent();
        if (dir == null) dir = ".";
        return new ProjectLocator(dir, name);
    }

    private String projectInfo() {
        try {
            Map<String, Object> data = new LinkedHashMap<>();
            Project active = AppInfo.getActiveProject();
            Project tp = tool != null ? tool.getProject() : null;
            Project chosen = active != null ? active : tp;
            data.put("project_open", chosen != null);
            if (chosen != null) {
                data.put("name", chosen.getName());
                ProjectLocator loc = chosen.getProjectLocator();
                if (loc != null) {
                    data.put("location", loc.getLocation());
                    data.put("path", new File(loc.getLocation(), loc.getName() + ProjectLocator.getProjectExtension()).getAbsolutePath());
                    data.put("locator", loc.toString());
                }
                data.put("has_changes", chosen.hasChanged());
                int files = 0;
                try { files = chosen.getProjectData().getFileCount(); } catch (Exception ignored) {}
                data.put("file_count", files);
            }
            data.put("tool_kind", tool != null ? tool.getName() : null);
            ProgramManager pm = tool != null ? tool.getService(ProgramManager.class) : null;
            Program current = pm != null ? pm.getCurrentProgram() : null;
            data.put("current_program", current != null ? current.getName() : null);
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("project_info error: " + e.getMessage());
        }
    }

    private String openProject(Map<String, String> params) {
        try {
            String path = required(params.get("path"), "path");
            ProjectManager pm = getProjectManager();
            if (pm == null) return jsonError("ProjectManager not available");
            ProjectLocator locator = parseProjectLocator(path);
            if (!pm.projectExists(locator)) return jsonError("project not found: " + locator);
            AtomicReference<Project> opened = new AtomicReference<>();
            StringBuilder err = new StringBuilder();
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Project existing = pm.getActiveProject();
                    if (existing != null) {
                        ProjectLocator existingLoc = existing.getProjectLocator();
                        if (existingLoc != null && existingLoc.equals(locator)) {
                            opened.set(existing);
                            return;
                        }
                        FrontEndTool fe = AppInfo.getFrontEndTool();
                        if (fe != null) {
                            try {
                                fe.setActiveProject(null);
                            } catch (Exception ignored) {}
                        }
                        try { existing.close(); } catch (Exception ignored) {}
                    }
                    Project p = pm.openProject(locator, true, true);
                    if (p == null) { err.append("openProject returned null"); return; }
                    FrontEndTool fe = AppInfo.getFrontEndTool();
                    if (fe != null) {
                        try { fe.setActiveProject(p); } catch (Exception ignored) {}
                    } else {
                        AppInfo.setActiveProject(p);
                    }
                    opened.set(p);
                } catch (Throwable t) {
                    err.append(t.getMessage() == null ? t.toString() : t.getMessage());
                }
            });
            if (opened.get() == null) return jsonError("open_project failed: " + err);
            Project p = opened.get();
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("name", p.getName());
            r.put("locator", p.getProjectLocator() != null ? p.getProjectLocator().toString() : null);
            return jsonOk(r);
        } catch (Exception e) {
            return jsonError("open_project error: " + e.getMessage());
        }
    }

    private String closeProject(Map<String, String> params) {
        try {
            boolean save = !"0".equals(params.get("save")) && !"false".equalsIgnoreCase(params.get("save"));
            Project p = AppInfo.getActiveProject();
            if (p == null && tool != null) p = tool.getProject();
            if (p == null) return jsonError("no active project");
            final Project fp = p;
            final String name = p.getName();
            StringBuilder err = new StringBuilder();
            AtomicBoolean ok = new AtomicBoolean(false);
            SwingUtilities.invokeAndWait(() -> {
                try {
                    if (save) {
                        try { fp.save(); } catch (Exception ignored) {}
                    }
                    FrontEndTool fe = AppInfo.getFrontEndTool();
                    if (fe != null) {
                        try { fe.setActiveProject(null); } catch (Exception ignored) {}
                    } else {
                        AppInfo.setActiveProject(null);
                    }
                    try { fp.close(); } catch (Exception ignored) {}
                    ok.set(true);
                } catch (Throwable t) {
                    err.append(t.getMessage() == null ? t.toString() : t.getMessage());
                }
            });
            if (!ok.get()) return jsonError("close_project failed: " + err);
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("name", name);
            r.put("saved", save);
            return jsonOk(r);
        } catch (Exception e) {
            return jsonError("close_project error: " + e.getMessage());
        }
    }

    private String createProject(Map<String, String> params) {
        try {
            String path = required(params.get("path"), "path");
            String nameParam = params.get("name");
            ProjectManager pm = getProjectManager();
            if (pm == null) return jsonError("ProjectManager not available");
            File dir = new File(path);
            if (!dir.exists() && !dir.mkdirs()) return jsonError("cannot create directory: " + path);
            if (!dir.isDirectory()) return jsonError("not a directory: " + path);
            String name = (nameParam != null && !nameParam.isEmpty()) ? nameParam : dir.getName();
            ProjectLocator locator = new ProjectLocator(dir.getAbsolutePath(), name);
            if (pm.projectExists(locator)) return jsonError("project already exists: " + locator);
            AtomicReference<Project> created = new AtomicReference<>();
            StringBuilder err = new StringBuilder();
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Project p = pm.createProject(locator, null, true);
                    created.set(p);
                    FrontEndTool fe = AppInfo.getFrontEndTool();
                    if (fe != null) {
                        try { fe.setActiveProject(p); } catch (Exception ignored) {}
                    } else {
                        AppInfo.setActiveProject(p);
                    }
                } catch (Throwable t) {
                    err.append(t.getMessage() == null ? t.toString() : t.getMessage());
                }
            });
            if (created.get() == null) return jsonError("create_project failed: " + err);
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("name", created.get().getName());
            r.put("locator", locator.toString());
            return jsonOk(r);
        } catch (Exception e) {
            return jsonError("create_project error: " + e.getMessage());
        }
    }

    private String saveProject() {
        try {
            Project p = AppInfo.getActiveProject();
            if (p == null && tool != null) p = tool.getProject();
            if (p == null) return jsonError("no active project");
            final Project fp = p;
            StringBuilder err = new StringBuilder();
            AtomicBoolean ok = new AtomicBoolean(false);
            SwingUtilities.invokeAndWait(() -> {
                try {
                    fp.save();
                    ok.set(true);
                } catch (Throwable t) {
                    err.append(t.getMessage() == null ? t.toString() : t.getMessage());
                }
            });
            if (!ok.get()) return jsonError("save_project failed: " + err);
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("name", fp.getName());
            return jsonOk(r);
        } catch (Exception e) {
            return jsonError("save_project error: " + e.getMessage());
        }
    }

    private Project getActiveProjectOrError() {
        Project p = AppInfo.getActiveProject();
        if (p == null && tool != null) p = tool.getProject();
        return p;
    }

    private String listProjectFiles(Map<String, String> params) {
        try {
            Project p = getActiveProjectOrError();
            if (p == null) return jsonError("no active project");
            String folderPath = params.get("folder");
            if (folderPath == null || folderPath.isEmpty()) folderPath = "/";
            DomainFolder root = p.getProjectData().getFolder(folderPath);
            if (root == null) return jsonError("folder not found: " + folderPath);
            boolean recursive = !"0".equals(params.get("recursive"))
                && (params.get("recursive") == null
                    || "1".equals(params.get("recursive"))
                    || "true".equalsIgnoreCase(params.get("recursive")));
            List<Object> items = new ArrayList<>();
            collectDomainFiles(root, items, recursive);
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("folder", root.getPathname());
            data.put("count", items.size());
            data.put("items", items);
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("list_project_files error: " + e.getMessage());
        }
    }

    private void collectDomainFiles(DomainFolder folder, List<Object> out, boolean recursive) {
        for (DomainFile df : folder.getFiles()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", df.getName());
            m.put("path", df.getPathname());
            m.put("content_type", df.getContentType());
            Class<?> objClass = df.getDomainObjectClass();
            m.put("object_class", objClass != null ? objClass.getName() : null);
            m.put("read_only", df.isReadOnly());
            m.put("versioned", df.isVersioned());
            out.add(m);
        }
        if (recursive) {
            for (DomainFolder sub : folder.getFolders()) {
                collectDomainFiles(sub, out, true);
            }
        }
    }

    private String projectFileExists(Map<String, String> params) {
        try {
            Project p = getActiveProjectOrError();
            if (p == null) return jsonError("no active project");
            String path = required(params.get("path"), "path");
            DomainFile df = p.getProjectData().getFile(path);
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("path", path);
            data.put("exists", df != null);
            if (df != null) {
                data.put("content_type", df.getContentType());
                Class<?> objClass = df.getDomainObjectClass();
                data.put("object_class", objClass != null ? objClass.getName() : null);
            }
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("project_file_exists error: " + e.getMessage());
        }
    }

    private String deleteProjectFile(Map<String, String> params) {
        try {
            Project p = getActiveProjectOrError();
            if (p == null) return jsonError("no active project");
            String path = required(params.get("path"), "path");
            DomainFile df = p.getProjectData().getFile(path);
            if (df == null) return jsonError("project file not found: " + path);
            String name = df.getName();
            String pathOut = df.getPathname();
            StringBuilder err = new StringBuilder();
            AtomicBoolean ok = new AtomicBoolean(false);
            SwingUtilities.invokeAndWait(() -> {
                try {
                    df.delete();
                    ok.set(true);
                } catch (Throwable t) {
                    err.append(t.getMessage() == null ? t.toString() : t.getMessage());
                }
            });
            if (!ok.get()) return jsonError("delete failed: " + err);
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("name", name);
            r.put("path", pathOut);
            return jsonOk(r);
        } catch (Exception e) {
            return jsonError("delete_project_file error: " + e.getMessage());
        }
    }

    /** Resolve a loader by simple class name (LoaderService.getLoaderClassByName),
     *  by full class name, or by display name (Loader.getName). */
    private Class<? extends Loader> resolveLoaderClass(String name) {
        if (name == null) return null;
        Class<? extends Loader> c = LoaderService.getLoaderClassByName(name);
        if (c != null) return c;
        for (Loader loader : ClassSearcher.getInstances(Loader.class)) {
            Class<? extends Loader> lc = loader.getClass();
            if (lc.getName().equals(name) || loader.getName().equals(name)) return lc;
        }
        return null;
    }

    private String listLoaders() {
        try {
            // LoaderService.getAllLoaderNames() returns Loader.getName() (display name),
            // but LoaderService.getLoaderClassByName() matches by Class.getSimpleName().
            // The two namespaces can differ, so we resolve loader classes directly here
            // and expose both fields so callers can pick the one their downstream call needs.
            List<Object> items = new ArrayList<>();
            List<Loader> loaders = new ArrayList<>(ClassSearcher.getInstances(Loader.class));
            Collections.sort(loaders);
            for (Loader loader : loaders) {
                Map<String, Object> m = new LinkedHashMap<>();
                Class<? extends Loader> c = loader.getClass();
                m.put("name", loader.getName());
                m.put("loader_name", c.getSimpleName());
                m.put("class", c.getName());
                items.add(m);
            }
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("count", items.size());
            data.put("items", items);
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("list_loaders error: " + e.getMessage());
        }
    }

    private String listLanguages(Map<String, String> params) {
        try {
            LanguageService ls = DefaultLanguageService.getLanguageService();
            String processorFilter = trimOrNull(params.get("processor"));
            String idFilter = trimOrNull(params.get("language_id"));
            List<Object> items = new ArrayList<>();
            for (LanguageDescription ld : ls.getLanguageDescriptions(false)) {
                if (processorFilter != null && !ld.getProcessor().toString().equalsIgnoreCase(processorFilter)) continue;
                if (idFilter != null && !ld.getLanguageID().toString().equals(idFilter)) continue;
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("language_id", ld.getLanguageID().toString());
                m.put("processor", ld.getProcessor().toString());
                m.put("endian", ld.getEndian().toString());
                m.put("size", ld.getSize());
                m.put("variant", ld.getVariant());
                m.put("description", ld.getDescription());
                items.add(m);
            }
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("count", items.size());
            data.put("items", items);
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("list_languages error: " + e.getMessage());
        }
    }

    private String listCompilerSpecs(Map<String, String> params) {
        try {
            String languageIdStr = required(params.get("language_id"), "language_id");
            LanguageService ls = DefaultLanguageService.getLanguageService();
            Language lang;
            try {
                lang = ls.getLanguage(new LanguageID(languageIdStr));
            } catch (Exception ex) {
                return jsonError("unknown language_id: " + languageIdStr);
            }
            List<Object> items = new ArrayList<>();
            for (CompilerSpecDescription cd : lang.getCompatibleCompilerSpecDescriptions()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("compiler_spec_id", cd.getCompilerSpecID().toString());
                m.put("name", cd.getCompilerSpecName());
                items.add(m);
            }
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("language_id", languageIdStr);
            data.put("default", lang.getDefaultCompilerSpec().getCompilerSpecID().toString());
            data.put("count", items.size());
            data.put("items", items);
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("list_compiler_specs error: " + e.getMessage());
        }
    }

    // ----------------------------------------------------------------------------------
    // Async analysis
    // ----------------------------------------------------------------------------------

    private static final class AnalysisJob {
        final String id;
        final WeakReference<Program> programRef;
        final String programName;
        final ProgressTaskMonitor monitor;
        final long startedAt;
        volatile String state; // "queued","running","done","cancelled","error"
        volatile long endedAt;
        volatile String error;
        volatile int functionCountStart;
        volatile int functionCountEnd;
        Thread worker;

        AnalysisJob(String id, Program p) {
            this.id = id;
            this.programRef = new WeakReference<>(p);
            this.programName = p.getName();
            this.monitor = new ProgressTaskMonitor();
            this.startedAt = System.currentTimeMillis();
            this.state = "queued";
            this.functionCountStart = p.getFunctionManager().getFunctionCount();
            this.functionCountEnd = this.functionCountStart;
        }

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("job_id", id);
            m.put("program", programName);
            m.put("state", state);
            m.put("started_at", startedAt);
            m.put("ended_at", endedAt);
            m.put("elapsed_ms", (endedAt > 0 ? endedAt : System.currentTimeMillis()) - startedAt);
            m.put("cancelled", monitor.isCancelled());
            m.put("max", monitor.getMaximum());
            m.put("progress", monitor.getProgress());
            double percent = -1.0;
            long max = monitor.getMaximum();
            if (max > 0) percent = 100.0 * monitor.getProgress() / max;
            m.put("percent", percent);
            m.put("current_task", monitor.getMessage());
            m.put("function_count_start", functionCountStart);
            m.put("function_count", functionCountEnd);
            m.put("error", error);
            return m;
        }
    }

    private static final class ProgressTaskMonitor extends ghidra.util.task.TaskMonitorAdapter {
        private volatile long max = 0;
        private volatile long progress = 0;
        private volatile String message = "";
        ProgressTaskMonitor() { super(true); }
        @Override public void setMessage(String m) { this.message = m == null ? "" : m; }
        @Override public String getMessage() { return message; }
        @Override public void setMaximum(long max) { this.max = max; }
        @Override public long getMaximum() { return max; }
        @Override public void setProgress(long value) { this.progress = value; }
        @Override public void incrementProgress(long incrementAmount) { this.progress += incrementAmount; }
        @Override public long getProgress() { return progress; }
        @Override public void initialize(long max) { this.max = max; this.progress = 0; }
    }

    private String startAnalysis(Map<String, String> params) {
        try {
            Program program = getCurrentProgram();
            if (program == null) return jsonError("No program loaded");
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
            if (mgr.isAnalyzing()) {
                return jsonError("analysis already running");
            }
            boolean reanalyze = "1".equals(params.get("reanalyze"))
                || "true".equalsIgnoreCase(params.get("reanalyze"));
            String id = "job-" + analysisJobCounter.getAndIncrement();
            AnalysisJob job = new AnalysisJob(id, program);
            analysisJobs.put(id, job);
            final Program prog = program;
            Thread t = new Thread(() -> {
                int tx = -1;
                try {
                    job.state = "running";
                    tx = prog.startTransaction("start_analysis " + id);
                    if (reanalyze) mgr.reAnalyzeAll(null);
                    mgr.startAnalysis(job.monitor);
                    job.state = job.monitor.isCancelled() ? "cancelled" : "done";
                } catch (Throwable th) {
                    job.error = th.getMessage() == null ? th.toString() : th.getMessage();
                    job.state = "error";
                } finally {
                    if (tx >= 0) {
                        try { prog.endTransaction(tx, true); } catch (Exception ignored) {}
                    }
                    job.endedAt = System.currentTimeMillis();
                    try { job.functionCountEnd = prog.getFunctionManager().getFunctionCount(); } catch (Exception ignored) {}
                }
            }, "GhidraMCP-Analysis-" + id);
            t.setDaemon(true);
            job.worker = t;
            t.start();
            return jsonOk(job.toMap());
        } catch (Exception e) {
            return jsonError("start_analysis error: " + e.getMessage());
        }
    }

    private String analysisProgress(Map<String, String> params) {
        try {
            String jobId = trimOrNull(params.get("job_id"));
            if (jobId == null) {
                // Return all jobs
                List<Object> items = new ArrayList<>();
                for (AnalysisJob j : analysisJobs.values()) items.add(j.toMap());
                Map<String, Object> data = new LinkedHashMap<>();
                data.put("count", items.size());
                data.put("items", items);
                return jsonOk(data);
            }
            AnalysisJob job = analysisJobs.get(jobId);
            if (job == null) return jsonError("unknown job_id: " + jobId);
            return jsonOk(job.toMap());
        } catch (Exception e) {
            return jsonError("analysis_progress error: " + e.getMessage());
        }
    }

    private String cancelAnalysis(Map<String, String> params) {
        try {
            String jobId = required(params.get("job_id"), "job_id");
            AnalysisJob job = analysisJobs.get(jobId);
            if (job == null) return jsonError("unknown job_id: " + jobId);
            job.monitor.cancel();
            Program p = job.programRef.get();
            if (p != null) {
                try {
                    AutoAnalysisManager.getAnalysisManager(p).cancelQueuedTasks();
                } catch (Exception ignored) {}
            }
            return jsonOk(job.toMap());
        } catch (Exception e) {
            return jsonError("cancel_analysis error: " + e.getMessage());
        }
    }

    // ----------------------------------------------------------------------------------
    // Readiness probe, navigation
    // ----------------------------------------------------------------------------------

    private static final String SCALAR_OPERAND_ANALYZER = "Scalar Operand References";
    private static final String ELF_SCALAR_OPERAND_ANALYZER = "ELF Scalar Operand References";

    /** Build a list of agent-facing capability hints. These are surfaced from
     *  the endpoints an agent typically calls to "check the server" (`/ready`,
     *  `/program_info`, `/agent_hints`) so agents discover what they can do
     *  on their own, instead of asking the user. */
    private List<String> buildAgentHints(Project project, Program current) {
        List<String> hints = new ArrayList<>();

        // Loading state
        if (project == null) {
            hints.add("No project open. You can open or create one yourself: " +
                "open_project(path) / create_project(path) / list_project_files.");
        }
        if (current == null) {
            hints.add("No current program. You don't need the user to load a binary — " +
                "use import_file(path) to import from disk, open_program(project_path) " +
                "to open one already in the project, or bring_up(rom_path, ...) for a " +
                "one-shot import+analyze. list_open_programs and select_program switch " +
                "between already-open programs.");
        }

        // Scalar Operand References analyzer — disabled by default in stock Ghidra,
        // but on dense ARM/Thumb / large stripped binaries enabling it can reveal
        // tens of thousands of additional function starts. Worth always recommending.
        if (current != null) {
            try {
                Options opts = current.getOptions(Program.ANALYSIS_PROPERTIES);
                boolean scalarOn = opts.getBoolean(SCALAR_OPERAND_ANALYZER, false);
                boolean elfScalarOn = opts.contains(ELF_SCALAR_OPERAND_ANALYZER)
                    ? opts.getBoolean(ELF_SCALAR_OPERAND_ANALYZER, false) : true;
                if (!scalarOn) {
                    hints.add("CRITICAL: the 'Scalar Operand References' analyzer is " +
                        "disabled (Ghidra default). Enabling it on dense binaries can " +
                        "reveal 28,000+ additional function references. Run: " +
                        "enable_analyzer(name=\"Scalar Operand References\") then " +
                        "analyze() — or analyze_range(start, end) for a scoped re-run.");
                }
                if (!elfScalarOn && opts.contains(ELF_SCALAR_OPERAND_ANALYZER)) {
                    hints.add("ELF binaries: 'ELF Scalar Operand References' is also " +
                        "disabled. Run: enable_analyzer(name=\"ELF Scalar Operand " +
                        "References\") then analyze().");
                }
            } catch (Exception ignored) {}
        } else {
            hints.add("After loading a program, enable the 'Scalar Operand References' " +
                "analyzer (Ghidra disables it by default). On dense binaries it can " +
                "reveal 28,000+ additional function references. Run: " +
                "enable_analyzer(name=\"Scalar Operand References\") then analyze().");
        }

        // ARM/Thumb workarounds — only surface when the loaded program is ARM,
        // to avoid noise for other architectures.
        if (current != null) {
            try {
                String procName = current.getLanguage().getProcessor().toString();
                if (procName != null && procName.equalsIgnoreCase("ARM")) {
                    hints.add("ARM/Thumb: Ghidra often misses PC-relative ldr [pc, #imm] " +
                        "references — call propagate_ldr_pc_refs() after analysis. " +
                        "Constant-pool function pointers default to ARM disassembly even " +
                        "when their low bit marks them as Thumb — use " +
                        "create_thumb_function_from_pointer(pointer_address) or " +
                        "scan_thumb_pointer_table(start, end).");
                }
            } catch (Exception ignored) {}
        }

        return hints;
    }

    /** Simple endpoint that returns just the agent hints, for fast self-discovery
     *  without pulling the full `/ready` payload. */
    private String agentHints() {
        try {
            Project proj = AppInfo.getActiveProject();
            if (proj == null && tool != null) proj = tool.getProject();
            ProgramManager pm = tool != null ? tool.getService(ProgramManager.class) : null;
            Program current = pm != null ? pm.getCurrentProgram() : null;
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("hints", buildAgentHints(proj, current));
            return jsonOk(out);
        } catch (Exception e) {
            return jsonError("agent_hints error: " + e.getMessage());
        }
    }

    private String ready() {
        try {
            Map<String, Object> data = new LinkedHashMap<>();
            Project proj = AppInfo.getActiveProject();
            if (proj == null && tool != null) proj = tool.getProject();
            data.put("project_open", proj != null);
            if (proj != null) {
                data.put("project_name", proj.getName());
                ProjectLocator loc = proj.getProjectLocator();
                data.put("project_path", loc != null
                    ? new File(loc.getLocation(), loc.getName() + ProjectLocator.getProjectExtension()).getAbsolutePath()
                    : null);
            } else {
                data.put("project_name", null);
                data.put("project_path", null);
            }
            data.put("tool_kind", tool != null ? tool.getName() : null);
            ProgramManager pm = tool != null ? tool.getService(ProgramManager.class) : null;
            Program current = pm != null ? pm.getCurrentProgram() : null;
            if (current != null) {
                Map<String, Object> cm = new LinkedHashMap<>();
                cm.put("name", current.getName());
                DomainFile df = current.getDomainFile();
                cm.put("path", df != null ? df.getPathname() : null);
                cm.put("language", current.getLanguage().getLanguageID().toString());
                cm.put("compiler_spec", current.getCompilerSpec().getCompilerSpecID().toString());
                cm.put("image_base", current.getImageBase().toString());
                cm.put("function_count", current.getFunctionManager().getFunctionCount());
                try {
                    AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(current);
                    cm.put("analyzing", mgr.isAnalyzing());
                } catch (Exception ignored) {
                    cm.put("analyzing", false);
                }
                data.put("current_program", cm);
            } else {
                data.put("current_program", null);
            }
            List<Object> openPrograms = new ArrayList<>();
            if (pm != null) {
                for (Program p : pm.getAllOpenPrograms()) {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("name", p.getName());
                    DomainFile df = p.getDomainFile();
                    m.put("path", df != null ? df.getPathname() : null);
                    openPrograms.add(m);
                }
            }
            data.put("open_programs", openPrograms);
            // Active analysis jobs summary
            List<Object> jobs = new ArrayList<>();
            for (AnalysisJob j : analysisJobs.values()) {
                if ("running".equals(j.state) || "queued".equals(j.state)) jobs.add(j.toMap());
            }
            data.put("active_analysis_jobs", jobs);
            data.put("agent_hints", buildAgentHints(proj, current));
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("ready error: " + e.getMessage());
        }
    }

    private String gotoAddress(Map<String, String> params) {
        try {
            Program program = getCurrentProgram();
            if (program == null) return jsonError("No program loaded");
            String addressStr = required(params.get("address"), "address");
            Address addr = parseAddress(program, addressStr);
            if (addr == null) return jsonError("bad address: " + addressStr);
            GoToService gts = tool.getService(GoToService.class);
            AtomicBoolean ok = new AtomicBoolean(false);
            SwingUtilities.invokeAndWait(() -> {
                if (gts != null) {
                    ok.set(gts.goTo(addr, program));
                } else {
                    // Fallback: just record the cursor by directly calling the code viewer if available.
                    CodeViewerService cvs = tool.getService(CodeViewerService.class);
                    if (cvs != null) {
                        ok.set(cvs.goTo(new ProgramLocation(program, addr), true));
                    }
                }
            });
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("address", addr.toString());
            r.put("ok", ok.get());
            return jsonOk(r);
        } catch (Exception e) {
            return jsonError("goto error: " + e.getMessage());
        }
    }

    private String selectRange(Map<String, String> params) {
        try {
            Program program = getCurrentProgram();
            if (program == null) return jsonError("No program loaded");
            String startStr = required(params.get("start"), "start");
            String endStr = required(params.get("end"), "end");
            Address start = parseAddress(program, startStr);
            Address end = parseAddress(program, endStr);
            if (start == null || end == null) return jsonError("bad address");
            GoToService gts = tool.getService(GoToService.class);
            AtomicBoolean ok = new AtomicBoolean(false);
            SwingUtilities.invokeAndWait(() -> {
                try {
                    AddressSet set = new AddressSet(start, end);
                    ProgramSelection sel = new ProgramSelection(set);
                    if (gts != null && gts.getDefaultNavigatable() != null) {
                        gts.getDefaultNavigatable().setSelection(sel);
                        gts.goTo(start, program);
                        ok.set(true);
                    }
                } catch (Exception ignored) {}
            });
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("start", start.toString());
            r.put("end", end.toString());
            r.put("ok", ok.get());
            return jsonOk(r);
        } catch (Exception e) {
            return jsonError("select_range error: " + e.getMessage());
        }
    }

    // ----------------------------------------------------------------------------------
    // GBA memory map helper
    // ----------------------------------------------------------------------------------

    private static final Object[][] GBA_REGIONS = {
        // name, start, size, read, write, execute, initialized
        {"BIOS",       0x00000000L, 0x4000L,    true, false, true, false},
        {"EWRAM",      0x02000000L, 0x40000L,   true, true,  true, false},
        {"IWRAM",      0x03000000L, 0x8000L,    true, true,  true, false},
        {"IO",         0x04000000L, 0x400L,     true, true,  false, false},
        {"Palette",    0x05000000L, 0x400L,     true, true,  false, false},
        {"VRAM",       0x06000000L, 0x18000L,   true, true,  false, false},
        {"OAM",        0x07000000L, 0x400L,     true, true,  false, false},
        {"ROM_MIRROR", 0x0A000000L, 0x2000000L, true, false, true, false},
        {"SRAM",       0x0E000000L, 0x10000L,   true, true,  false, false},
    };

    private String ensureGbaMemoryMap(Map<String, String> params) {
        try {
            Program program = getCurrentProgram();
            if (program == null) return jsonError("No program loaded");
            boolean overwrite = "1".equals(params.get("overwrite"))
                || "true".equalsIgnoreCase(params.get("overwrite"));
            List<Object> created = new ArrayList<>();
            List<Object> skipped = new ArrayList<>();
            StringBuilder err = new StringBuilder();
            AtomicBoolean ok = new AtomicBoolean(false);
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("ensure_gba_memory_map");
                try {
                    Memory mem = program.getMemory();
                    for (Object[] region : GBA_REGIONS) {
                        String name = (String) region[0];
                        long startAddr = (long) region[1];
                        long size = (long) region[2];
                        boolean read = (boolean) region[3];
                        boolean write = (boolean) region[4];
                        boolean execute = (boolean) region[5];
                        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(startAddr);
                        MemoryBlock existing = mem.getBlock(start);
                        if (existing != null && !overwrite) {
                            Map<String, Object> m = new LinkedHashMap<>();
                            m.put("name", name);
                            m.put("existing_block", existing.getName());
                            m.put("start", existing.getStart().toString());
                            skipped.add(m);
                            continue;
                        }
                        if (existing != null) {
                            mem.removeBlock(existing, new ConsoleTaskMonitor());
                        }
                        MemoryBlock blk = mem.createUninitializedBlock(name, start, size, false);
                        blk.setRead(read);
                        blk.setWrite(write);
                        blk.setExecute(execute);
                        Map<String, Object> m = new LinkedHashMap<>();
                        m.put("name", blk.getName());
                        m.put("start", blk.getStart().toString());
                        m.put("end", blk.getEnd().toString());
                        m.put("size", blk.getSize());
                        created.add(m);
                    }
                    ok.set(true);
                } catch (Throwable th) {
                    err.append(th.getMessage() == null ? th.toString() : th.getMessage());
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
            if (!ok.get()) return jsonError("ensure_gba_memory_map failed: " + err);
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("created", created);
            data.put("skipped", skipped);
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("ensure_gba_memory_map error: " + e.getMessage());
        }
    }

    // ----------------------------------------------------------------------------------
    // One-shot bring-up
    // ----------------------------------------------------------------------------------

    private String bringUp(Map<String, String> params) {
        Map<String, Object> data = new LinkedHashMap<>();
        try {
            String romPath = required(params.get("rom_path"), "rom_path");
            String projectPath = trimOrNull(params.get("project_path"));
            String loaderName = trimOrNull(params.get("loader_name"));
            String languageId = trimOrNull(params.get("language_id"));
            String compilerSpec = trimOrNull(params.get("compiler_spec"));
            String imageBase = trimOrNull(params.get("image_base"));
            String loaderOptions = trimOrNull(params.get("loader_options"));
            String folder = trimOrNull(params.get("folder"));
            boolean ensureGba = "1".equals(params.get("ensure_gba"))
                || "true".equalsIgnoreCase(params.get("ensure_gba"));
            boolean analyze = !"0".equals(params.get("analyze"))
                && !"false".equalsIgnoreCase(params.get("analyze"));
            long waitMs = parseLongOrDefault(params.get("wait_ms"), 0);
            String seedAddressesRaw = trimOrNull(params.get("seed_addresses"));
            boolean seedImageBase = "1".equals(params.get("seed_image_base"))
                || "true".equalsIgnoreCase(params.get("seed_image_base"));

            // 1. Open project if requested
            if (projectPath != null) {
                Project active = getActiveProjectOrError();
                ProjectLocator wanted = parseProjectLocator(projectPath);
                if (active == null || active.getProjectLocator() == null
                        || !active.getProjectLocator().equals(wanted)) {
                    Map<String, String> p = new HashMap<>();
                    p.put("path", projectPath);
                    String resp = openProject(p);
                    data.put("open_project", parseJsonEnvelope(resp));
                    if (resp.contains("\"ok\":false")) return jsonError("bring_up: open_project failed");
                } else {
                    data.put("project_opened", true);
                }
            }

            Project project = getActiveProjectOrError();
            if (project == null) return jsonError("bring_up: no active project");

            // 2. Decide: is the ROM already imported?
            File romFile = new File(romPath);
            String desiredFolder = (folder == null || folder.isEmpty()) ? "/" : folder;
            if (!desiredFolder.startsWith("/")) desiredFolder = "/" + desiredFolder;
            String fileName = romFile.getName();
            String expectedProjectPath = (desiredFolder.equals("/") ? "/" : desiredFolder + "/") + fileName;
            DomainFile existing = project.getProjectData().getFile(expectedProjectPath);
            String programPath;
            if (existing == null) {
                // Try a permissive search for the file by name
                existing = findDomainFileByName(project.getProjectData().getRootFolder(), fileName);
            }
            if (existing == null) {
                Map<String, String> p = new HashMap<>();
                p.put("path", romPath);
                if (folder != null) p.put("folder", folder);
                if (loaderName != null) p.put("loader_name", loaderName);
                if (languageId != null) p.put("language_id", languageId);
                if (compilerSpec != null) p.put("compiler_spec", compilerSpec);
                if (imageBase != null) p.put("image_base", imageBase);
                if (loaderOptions != null) p.put("loader_options", loaderOptions);
                p.put("open", "1");
                String impResp = importFile(p);
                data.put("import_file", parseJsonEnvelope(impResp));
                if (impResp.contains("\"ok\":false")) return jsonError("bring_up: import_file failed");
                Map<?, ?> impData = (Map<?, ?>) data.get("import_file");
                programPath = impData != null ? String.valueOf(impData.get("path")) : null;
            } else {
                Map<String, String> p = new HashMap<>();
                p.put("path", existing.getPathname());
                String openResp = openProgram(p);
                data.put("open_program", parseJsonEnvelope(openResp));
                if (openResp.contains("\"ok\":false")) return jsonError("bring_up: open_program failed");
                programPath = existing.getPathname();
            }
            data.put("program_path", programPath);

            // 3. ensure_gba memory map
            if (ensureGba) {
                Map<String, String> p = new HashMap<>();
                String mapResp = ensureGbaMemoryMap(p);
                data.put("ensure_gba_memory_map", parseJsonEnvelope(mapResp));
            }

            // 3b. Seed disassembly so the analyzer has entry points to follow.
            // Raw-binary loaders don't seed entries themselves, so analysis would
            // otherwise discover 0 functions. Callers pass the addresses (e.g. reset/
            // interrupt vectors); we don't bake any platform-specific knowledge in.
            List<String> seedTargets = new ArrayList<>();
            Program currentForSeed = getCurrentProgram();
            if (seedImageBase && currentForSeed != null) {
                seedTargets.add(currentForSeed.getImageBase().toString());
            }
            if (seedAddressesRaw != null) {
                for (String s : seedAddressesRaw.split(",")) {
                    String t = s.trim();
                    if (!t.isEmpty()) seedTargets.add(t);
                }
            }
            if (!seedTargets.isEmpty()) {
                List<Object> seedResults = new ArrayList<>();
                for (String addr : seedTargets) {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("address", addr);
                    entry.put("result", disassembleAt(addr));
                    seedResults.add(entry);
                }
                data.put("disassemble_seeds", seedResults);
            }

            // 4. Start analysis (async)
            String jobId = null;
            if (analyze) {
                String anaResp = startAnalysis(new HashMap<>());
                Map<?, ?> anaData = parseJsonEnvelope(anaResp);
                data.put("start_analysis", anaData);
                if (anaData != null && anaData.get("job_id") != null) {
                    jobId = String.valueOf(anaData.get("job_id"));
                }
            }
            data.put("job_id", jobId);

            // 5. Wait if requested
            if (jobId != null && waitMs > 0) {
                long deadline = System.currentTimeMillis() + waitMs;
                AnalysisJob job = analysisJobs.get(jobId);
                while (job != null && System.currentTimeMillis() < deadline) {
                    if (!"running".equals(job.state) && !"queued".equals(job.state)) break;
                    try { Thread.sleep(250); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); break; }
                }
                if (job != null) data.put("analysis_state", job.toMap());
            }

            Program current = getCurrentProgram();
            data.put("function_count", current != null ? current.getFunctionManager().getFunctionCount() : -1);
            return jsonOk(data);
        } catch (Exception e) {
            return jsonError("bring_up error: " + e.getMessage());
        }
    }

    private DomainFile findDomainFileByName(DomainFolder folder, String name) {
        for (DomainFile df : folder.getFiles()) {
            if (df.getName().equals(name)) return df;
        }
        for (DomainFolder sub : folder.getFolders()) {
            DomainFile r = findDomainFileByName(sub, name);
            if (r != null) return r;
        }
        return null;
    }

    /** Minimal JSON-envelope parse: extracts the "data" object as a Map, for chaining responses. */
    private Map<?, ?> parseJsonEnvelope(String json) {
        // Best-effort: not robust JSON parser, just enough for the data shapes we emit.
        // For complex shapes we just embed the raw JSON string.
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("raw", json);
        return m;
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
