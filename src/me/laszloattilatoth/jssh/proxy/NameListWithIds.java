package me.laszloattilatoth.jssh.proxy;

import java.util.Arrays;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class NameListWithIds {
    private String originalNameList;
    private String nameList;
    private String[] removedNameList;
    private int[] nameIdList;

    private NameListWithIds(String nameList) {
        this.originalNameList = nameList;
        this.nameList = Arrays.stream(nameList.split(","))
                .filter(Name::hasName)
                .collect(Collectors.joining(","));
        this.removedNameList = Arrays.stream(nameList.split(","))
                .filter(Name::isUnknownName)
                .toArray(String[]::new);
        this.nameIdList = Arrays.stream(nameList.split(","))
                .filter(Name::hasName)
                .map(Name::getNameId)
                .mapToInt(x -> x)
                .toArray();
    }

    public static NameListWithIds create(String nameList) {
        return new NameListWithIds(nameList);
    }

    public static NameListWithIds createAndLog(String nameList, Logger logger, String name) {
        NameListWithIds n = new NameListWithIds(nameList);
        n.log(logger, name);
        return n;
    }

    public String getOriginalNameList() {
        return originalNameList;
    }

    public String getNameList() {
        return nameList;
    }

    public String[] getRemovedNameList() {
        return removedNameList;
    }

    public int[] getNameIdList() {
        return nameIdList;
    }

    public void log(Logger logger, String nameListName) {
        logger.info(()->String.format(
                "Name list '%s': effective_list='%s', complete_list='%s', removed_list='%s'",
                nameListName,
                nameList,
                originalNameList,
                String.join(",", removedNameList)
                ));
    }
}
