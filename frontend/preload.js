const { contextBridge } = require("electron");
const { exec } = require("child_process");
const path = require("path");

// caminho absoluto para o script Python
const script = path.join(__dirname, "../backend/socintel.py");

contextBridge.exposeInMainWorld("socintel", {
  analyze: (type, value) => {
    return new Promise((resolve, reject) => {
      const cmd = `python3 "${script}" --${type} "${value}" --json`;

      exec(cmd, (error, stdout, stderr) => {
        if (error) {
          reject(stderr || error.message);
        } else {
          try {
            resolve(JSON.parse(stdout));
          } catch (e) {
            reject("Saída inválida do Python:\n" + stdout);
          }
        }
      });
    });
  }
});
