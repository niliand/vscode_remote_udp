// ExtensionController.ts
export class ExtensionController {
  private folderPath = '';

  setFolderPath(p: string) {
    this.folderPath = p;
  }

  getFolderPath() {
    return this.folderPath;
  }
}

export const controller = new ExtensionController();
