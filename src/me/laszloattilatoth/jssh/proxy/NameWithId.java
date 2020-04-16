package me.laszloattilatoth.jssh.proxy;

public class NameWithId {

    private final String name;
    private final int nameId;

    public NameWithId(String name, int nameId) {
        this.name = name;
        this.nameId = nameId;
    }

    public NameWithId(int nameId) {
        this.name = Name.getName(nameId);
        this.nameId = nameId;
    }

    public String getName() {
        return name;
    }

    public int getNameId() {
        return nameId;
    }
}
