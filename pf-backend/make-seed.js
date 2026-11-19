// Regenerates seed.json (demo data) from the web app's built-in demo arrays.
//   node make-seed.js ../pratishtha.html
const vm=require('vm'),fs=require('fs');
const html=fs.readFileSync(process.argv[2]||'public/index.html','utf8');
const a=html.indexOf('const DC=['), b=html.indexOf('const DKYC_STATUS={};');
const src=html.slice(a,html.indexOf('//  HELPERS',a)).replace(/^const /gm,'var ').replace(/^let /gm,'var ');
const k0=html.indexOf('const DKYC_STATUS={};'), k1=html.indexOf('async function ldKYC',k0);
const kyc=html.slice(k0,k1).replace(/^const /gm,'var ');
const sb={console,Date,Math,tdy:()=>new Date().toISOString().slice(0,10),F:x=>x};vm.createContext(sb);
const e0=html.indexOf('// FINANCE-ENGINE-BEGIN'),e1=html.indexOf('// FINANCE-ENGINE-END');
const engine=html.slice(e0,e1).replace(/^const /gm,'var ');
vm.runInContext(src+'\n'+kyc+'\n'+engine+'\nbuildDemoJournal();',sb);
const m={DC:'customers',DL:'loans',DRD:'rds',DCOLS:'collections',DDEFS:'defaulters',DNOTIFS:'notifs',DBRANCHES:'branches',DLEADS:'leads',DUSERS:'users',DCOMMISSION:'commission',DLEAVES:'leaves',DSALARY:'salary',DBANK_ACCOUNTS:'bank_accounts',DVOUCHERS:'vouchers',DCAMPAIGNS:'campaigns',DPARTNERS:'partners',DPAYOUTS:'payouts',DPARTNER_TEAM:'partner_team',DCALLS:'calls',DACC_BANK:'acc_bank',DACC_INCOME:'acc_income',DACC_EXPENSE:'acc_expense',DACC_BASE:'acc_base',DLEAVE_BALANCE:'leave_balance',DKYC_STATUS:'kyc_status',DJOURNAL:'journal',DCLOSINGS:'closings',DCARDS:'cards',DLENDERS:'lenders',DRETAILERS:'retailers',DCOMM_LOG:'comm_log',DKYC_DOCS:'kyc_docs',DPAYOUT_RULES:'payout_rules',DMANDATES:'mandates',DESIGNS:'esigns',DCARD_TXNS:'card_txns',DPROOFS:'proofs',DGOLD:'gold_pledges',DAGRT:'agr_templates',DINS_PLANS:'ins_plans',DINS_POLICIES:'ins_policies',DINS_CLAIMS:'ins_claims'};
const out={};for(const [k,v] of Object.entries(m)){if(sb[k]===undefined)throw new Error('missing '+k);out[v]=JSON.parse(JSON.stringify(sb[k]));}
fs.writeFileSync(__dirname+'/seed.json',JSON.stringify(out));console.log('seed.json',Object.keys(out).length,'collections');
