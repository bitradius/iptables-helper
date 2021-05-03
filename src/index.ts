// Copyright (c) 2019-2021, BitRadius Holdings, LLC
//
// Please see the included LICENSE file for more information.

import { EventEmitter } from 'events';
import Cache from '@bitradius/memcache-helper';
import * as which from 'which';
import { exec } from 'child_process';
import { format } from 'util';

export default class extends EventEmitter {
    private readonly m_cache: Cache;
    private readonly m_iptables: string;

    /**
     * Constructs a new instance of the IPTables helper linked to the specific IPTables chain
     * @param m_chain
     * @param ttl
     */
    constructor (private m_chain: string, ttl = 300) {
        super();

        this.m_cache = new Cache(ttl, Math.ceil(ttl * 0.1));

        this.m_cache.on('error', error => this.emit('error', error));
        this.m_cache.on('expired', async (key) => await this.del(key));

        this.m_iptables = which.sync('iptables', { nothrow: true }) || '/usr/sbin/iptables';
    }

    public on(event: 'error', listener: (error: Error) => void): this;

    public on(event: 'expired', listener: (key: any) => void): this;

    public on (event: any, listener: (...args: any[]) => void): this {
        return super.on(event, listener);
    }

    private async _add (ip: string, jump = 'ACCEPT', nothrow = false): Promise<void> {
        return new Promise((resolve, reject) => {
            const cmd = format('%s -A %s -s %s -j %s', this.m_iptables, this.m_chain, ip, jump);

            exec(cmd, (error) => {
                if (error && !nothrow) {
                    return reject(error);
                }

                return resolve();
            });
        });
    }

    /**
     * Adds a jump statement for the specified IP address to the IPTables chain
     * @param ip
     * @param jump
     */
    public async add (ip: string, jump = 'ACCEPT'): Promise<boolean> {
        if (!await this.m_cache.exists(ip)) {
            await this._add(ip, jump);

            await this.m_cache.set(ip, jump);

            return true;
        } else {
            const current_jump = await this.m_cache.get<boolean>(ip);

            await this.m_cache.set(ip, current_jump);

            return false;
        }
    }

    /**
     * Adds a jump statement for the specified interface to the IPTables chain
     * @param iface
     * @param jump
     * @param nothrow
     */
    public async addInterface (iface: string, jump = 'ACCEPT', nothrow = false): Promise<void> {
        return new Promise((resolve, reject) => {
            const cmd = format('%s -A %s -i %s -j %s', this.m_iptables, this.m_chain, iface, jump);

            exec(cmd, (error) => {
                if (error && !nothrow) {
                    return reject(error);
                }

                return resolve();
            });
        });
    }

    /**
     * Deletes the specified IP address from the IPTable chain
     * @param ip
     */
    public async del (ip: string): Promise<boolean> {
        if (!await this.m_cache.exists(ip)) {
            return false;
        }

        await this.m_cache.del(ip);

        try {
            await this.flush();
        } catch {
            return false;
        }

        const list = await this.list();

        const p = [];

        for (const [key, jump] of list) {
            p.push(this._add(key, jump));
        }

        await Promise.all(p);

        return true;
    }

    /**
     * Flushes the IPTables chain
     * @param nothrow
     */
    public async flush (nothrow = false): Promise<void> {
        return new Promise((resolve, reject) => {
            const cmd = format('%s -F %s', this.m_iptables, this.m_chain);

            exec(cmd, (error) => {
                if (error && !nothrow) {
                    return reject(error);
                }

                return resolve();
            });
        });
    }

    /**
     * Flushes the IPTables chain and clears our knowledge of all known entries
     */
    public async flushAll (): Promise<void> {
        await this.flush();

        await this.m_cache.flush();
    }

    /**
     * Bumps the keep alive time for the specified IP address in the list of known entries
     * @param ip
     */
    public async keepAlive (ip: string): Promise<boolean> {
        return this.add(ip);
    }

    /**
     * Returns a map of all known ip addresses and jump entries we know about
     */
    public async list (): Promise<Map<string, string>> {
        return this.m_cache.list();
    }
}
