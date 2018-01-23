package burp;

import java.awt.Component
import java.util.*
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.table.DefaultTableModel

class MessageEditorTab(val editable: Boolean) : IMessageEditorTab {
    val paramTypes = arrayOf("URL", "Body", "Cookie", "XML", "XML attr", "Multipart attr", "JSON")

    val tableModel = ParamTableModel(editable)
    val table = JTable(tableModel)
    lateinit var msg: ByteArray

    init {
        val tc = table.columnModel.getColumn(0)
        tc.cellEditor = table.getDefaultEditor(java.lang.Boolean::class.java)
        tc.cellRenderer = table.getDefaultRenderer(java.lang.Boolean::class.java)

        table.autoResizeMode = JTable.AUTO_RESIZE_OFF
        table.columnModel.getColumn(0).preferredWidth = 60
        table.columnModel.getColumn(1).preferredWidth = 60
        table.columnModel.getColumn(2).preferredWidth = 120
        table.columnModel.getColumn(3).preferredWidth = 300
    }

    override fun getMessage(): ByteArray {
        var disabledParams = tableModel.getDisabledParams()
        val requestInfo = BurpExtender.cb.helpers.analyzeRequest(msg)
        var headers = requestInfo.headers
        headers = headers.filter { !it.startsWith(BurpExtender.headerName) }
        if (disabledParams.size > 0) {
            headers.add(BurpExtender.headerName + disabledParams.joinToString(","))
        }
        return BurpExtender.cb.helpers.buildHttpMessage(headers, Arrays.copyOfRange(msg, requestInfo.bodyOffset, msg.size))
    }

    override fun isModified(): Boolean {
        return tableModel.modified
    }

    override fun getTabCaption(): String {
        return "Toggle Parameters"
    }

    override fun getSelectedData(): ByteArray? {
        return null
    }

    override fun getUiComponent(): Component {
        return JScrollPane(table)
    }

    override fun setMessage(content: ByteArray, isRequest: Boolean) {
        if(!isRequest) {
            return;
        }

        while(tableModel.rowCount > 0) {
            tableModel.removeRow(0)
        }

        msg = content
        val requestInfo = BurpExtender.cb.helpers.analyzeRequest(content)
        val disabledParams = Utils.getDisabledParams(requestInfo.headers)
        for(param in requestInfo.parameters) {
            tableModel.addRow(arrayOf(!disabledParams.contains(param.name), paramTypes[param.type.toInt()], param.name, param.value))
        }
    }

    override fun isEnabled(content: ByteArray, isRequest: Boolean): Boolean {
        if(!isRequest || !editable) {
            return false
        }
        val requestInfo = BurpExtender.cb.helpers.analyzeRequest(content)
        return requestInfo.parameters.size > 0;
    }
}


class ParamTableModel(val editable: Boolean) : DefaultTableModel(arrayOf("Enabled", "Type", "Name", "Value"), 0) {
    var modified = false

    override fun getColumnClass(column: Int): Class<*> {
        return if (column == 0) java.lang.Boolean::class.java else super.getColumnClass(column)
    }

    override fun isCellEditable(row: Int, column: Int): Boolean {
        return editable && column == 0
    }

    override fun setValueAt(value: Any?, row: Int, column: Int) {
        modified = true
        super.setValueAt(value, row, column)
    }

    fun getDisabledParams(): List<String> {
        var disabledParams = arrayListOf<String>()
        for(i in 0 .. (rowCount-1)) {
            if(!(getValueAt(i, 0) as Boolean)) {
                disabledParams.add(getValueAt(i, 2) as String)
            }
        }
        return disabledParams
    }
}


class MessageEditorTabFactory : IMessageEditorTabFactory {
    override fun createNewInstance(controller: IMessageEditorController?, editable: Boolean): IMessageEditorTab {
        return MessageEditorTab(editable)
    }
}


class HttpListener : IHttpListener {
    override fun processHttpMessage(toolFlag: Int, isRequest: Boolean, message: IHttpRequestResponse) {
        if(!isRequest) {
            return
        }
        val helpers = BurpExtender.cb.helpers
        var request = message.request
        var requestInfo = helpers.analyzeRequest(request)
        var disabledParams = Utils.getDisabledParams(requestInfo.headers)
        if(disabledParams.size > 0) {
            for (paramName in disabledParams) {
                for (param in requestInfo.parameters) {
                    if (param.name.equals(paramName)) {
                        request = helpers.removeParameter(request, param)
                    }
                }
            }
            requestInfo = BurpExtender.cb.helpers.analyzeRequest(request)
            var headers = requestInfo.headers
            headers = headers.filter { !it.startsWith(BurpExtender.headerName) }
            message.request = BurpExtender.cb.helpers.buildHttpMessage(headers, Arrays.copyOfRange(request, requestInfo.bodyOffset, request.size))
        }
    }
}


class BurpExtender : IBurpExtender {
    companion object {
        const val headerName = "X-Toggle-Parameters: "
        lateinit var cb: IBurpExtenderCallbacks
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        cb = callbacks
        cb.setExtensionName("Toggle Parameters")
        cb.registerMessageEditorTabFactory(MessageEditorTabFactory())
        cb.registerHttpListener(HttpListener())
    }
}


class Utils {
    companion object {
        fun getDisabledParams(headers: List<String>): List<String> {
            for(header in headers) {
                if(header.startsWith(BurpExtender.headerName)) {
                    return header.substringAfter(BurpExtender.headerName).split(",")
                }
            }
            return arrayListOf()
        }
    }
}
