export interface Note {
  id: string;
  body: string;
}

export class MemoryStore {
  private notes: Note[] = [];

  add(note: Note): Note {
    this.notes.push(note);
    return note;
  }

  find(id: string): Note | undefined {
    return this.notes.find((n) => n.id === id);
  }
}

export class AuditedStore extends MemoryStore {
  add(note: Note): Note {
    audit("add", note.id);
    return super.add(note);
  }
}

export function audit(action: string, id: string): void {
  console.log(action, id);
}

export default function createStore(): AuditedStore {
  return new AuditedStore();
}
