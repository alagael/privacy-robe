import {splitSeed,recoverSeed} from "../dist/index.js";
const fixture="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const shares=await splitSeed(fixture,2,3,"");
if(await recoverSeed(shares.slice(0,2),"")!==fixture) throw Error("Round trip failed");
console.log("Disposable public test vector: 2-of-3 recovery passed. Never fund this fixture.");
