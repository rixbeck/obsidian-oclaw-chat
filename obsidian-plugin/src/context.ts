import type { App } from 'obsidian';

export interface NoteContext {
  title: string;
  path: string;
  content: string;
}

/**
 * Returns the active note's title and content, or null if no note is open.
 * Async because vault.read() is async.
 */
export async function getActiveNoteContext(app: App): Promise<NoteContext | null> {
  const file = app.workspace.getActiveFile();
  if (!file) return null;

  try {
    const content = await app.vault.read(file);
    return {
      title: file.basename,
      path: file.path,
      content,
    };
  } catch (err) {
    console.error('[oclaw-context] Failed to read active note', err);
    return null;
  }
}
