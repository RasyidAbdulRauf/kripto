# Memuat paket yang diperlukan
library(shiny)
library(openssl)

# Definisi UI
ui <- fluidPage(
  titlePanel("Enkripsi dan Dekripsi File dengan AES-256"),
  sidebarLayout(
    sidebarPanel(
      fileInput("fileInput", "Pilih File untuk Enkripsi atau Dekripsi"),
      textInput("key", "Kunci Enkripsi (32 karakter untuk AES-256)"),
      actionButton("encrypt", "Enkripsi"),
      actionButton("decrypt", "Dekripsi"),
      downloadButton("downloadEncrypted", "Unduh File Terenkripsi"),
      downloadButton("downloadDecrypted", "Unduh File Terdekripsi"),
      textOutput("status")
    ),
    mainPanel(
      textOutput("status")
    )
  )
)

# Definisi Logika Server
server <- function(input, output, session) {
   # Nilai reaktif untuk menyimpan jalur file terenkripsi dan terdekripsi
   reactive_values <- reactiveValues(
      encryptedFile = NULL,
      decryptedFile = NULL
   )
   
   # Proses Enkripsi
   observeEvent(input$encrypt, {
      req(input$fileInput)
      req(nchar(input$key) == 32)  # Pastikan kunci terdiri dari 32 karakter untuk AES-256
      
      # Membaca konten file sebagai data biner mentah
      file_content <- readBin(input$fileInput$datapath, "raw", file.info(input$fileInput$datapath)$size)
      key <- charToRaw(input$key)
      
      # Menghasilkan Vektor Inisialisasi (IV) acak untuk mode CBC
      iv <- rand_bytes(16)  # 16 byte untuk ukuran blok AES
      
      # Mengenkripsi konten file
      encrypted_content <- tryCatch({
         aes_cbc_encrypt(file_content, key, iv = iv)
      }, error = function(e) {
         showNotification("Enkripsi gagal. Silakan periksa kunci atau format file.", type = "error")
         NULL  # Mengembalikan NULL jika enkripsi gagal
      })
      
      # Cek apakah enkripsi berhasil
      if (!is.null(encrypted_content)) {
         # Menyisipkan IV ke dalam konten terenkripsi
         encrypted_content_with_iv <- c(iv, encrypted_content)
         
         # Simpan konten terenkripsi ke file sementara dengan ekstensi .enc
         encrypted_file_path <- tempfile(fileext = ".enc")
         writeBin(encrypted_content_with_iv, encrypted_file_path)
         
         # Menyimpan jalur untuk diunduh
         reactive_values$encryptedFile <- encrypted_file_path
         output$downloadEncrypted <- downloadHandler(
            filename = function() {
               paste(input$fileInput$name, ".enc", sep = "")
            },
            content = function(file) {
               file.copy(reactive_values$encryptedFile, file)
            }
         )
         output$status <- renderText("File berhasil dienkripsi. Anda dapat mengunduhnya.")
         shinyjs::show("downloadEncrypted")  # Tampilkan tombol unduh file terenkripsi
      }
   })
   
   # Proses Dekripsi
   observeEvent(input$decrypt, {
      req(input$fileInput)
      req(nchar(input$key) == 32)  # Pastikan kunci terdiri dari 32 karakter untuk AES-256
      
      # Membaca konten file sebagai data biner mentah
      file_content <- readBin(input$fileInput$datapath, "raw", file.info(input$fileInput$datapath)$size)
      key <- charToRaw(input$key)
      
      # Mengambil IV dan konten terenkripsi
      iv <- file_content[1:16]  # 16 byte pertama adalah IV
      encrypted_content <- file_content[-(1:16)]  # Sisa byte adalah konten yang sebenarnya
      
      # Mendekripsi konten file
      decrypted_content <- tryCatch({
         aes_cbc_decrypt(encrypted_content, key, iv = iv)
      }, error = function(e) {
         showNotification("Dekripsi gagal. Silakan periksa kunci atau format file.", type = "error")
         NULL  # Mengembalikan NULL jika dekripsi gagal
      })
      
      # Cek apakah dekripsi berhasil
      if (!is.null(decrypted_content)) {
         # Simpan konten terdekripsi ke file sementara dengan ekstensi asli
         decrypted_file_path <- tempfile(fileext = tools::file_ext(input$fileInput$name))
         writeBin(decrypted_content, decrypted_file_path)
         
         # Menyimpan jalur untuk diunduh
         reactive_values$decryptedFile <- decrypted_file_path
         output$downloadDecrypted <- downloadHandler(
            filename = function() {
               tools::file_path_sans_ext(input$fileInput$name)  # Mengembalikan nama file asli
            },
            content = function(file) {
               file.copy(reactive_values$decryptedFile, file)
            }
         )
         output$status <- renderText("File berhasil didekripsi. Anda dapat mengunduhnya.")
         shinyjs::show("downloadDecrypted")  # Tampilkan tombol unduh file terdekripsi
      }
   })
}

# Jalankan aplikasi Shiny
shinyApp(ui = ui, server = server)
