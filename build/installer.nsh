; Verify a PDF: list Kukux Sign Agent under "Open with" for .pdf files,
; without ever becoming their default app.
;
; electron-builder's own fileAssociations (APP_ASSOCIATE) writes the default
; value of Software\Classes\.pdf, which can make the agent the PDF viewer.
; This only adds a ProgID and an OpenWithProgids entry, which Windows lists
; under "Open with" and never picks by itself. The ProgID launches the agent
; with the file path; the running agent receives it as second-instance argv.
; Per-user (nsis.perMachine is false), so SHCTX is HKCU.

!define KUKUX_PDF_PROGID "KukuxSignAgent.VerifyPdf"

!macro customInstall
  WriteRegStr SHCTX "Software\Classes\${KUKUX_PDF_PROGID}" "" "PDF document"
  WriteRegStr SHCTX "Software\Classes\${KUKUX_PDF_PROGID}" "FriendlyTypeName" "PDF document"
  WriteRegStr SHCTX "Software\Classes\${KUKUX_PDF_PROGID}\DefaultIcon" "" "$\"$INSTDIR\${APP_EXECUTABLE_FILENAME}$\",0"
  WriteRegStr SHCTX "Software\Classes\${KUKUX_PDF_PROGID}\shell\open" "FriendlyAppName" "${PRODUCT_NAME}"
  WriteRegStr SHCTX "Software\Classes\${KUKUX_PDF_PROGID}\shell\open\command" "" "$\"$INSTDIR\${APP_EXECUTABLE_FILENAME}$\" $\"%1$\""
  WriteRegNone SHCTX "Software\Classes\.pdf\OpenWithProgids" "${KUKUX_PDF_PROGID}"
  System::Call "shell32::SHChangeNotify(i 0x08000000, i 0x1000, p 0, p 0)"
!macroend

!macro customUnInstall
  DeleteRegValue SHCTX "Software\Classes\.pdf\OpenWithProgids" "${KUKUX_PDF_PROGID}"
  DeleteRegKey SHCTX "Software\Classes\${KUKUX_PDF_PROGID}"
  System::Call "shell32::SHChangeNotify(i 0x08000000, i 0x1000, p 0, p 0)"
!macroend
